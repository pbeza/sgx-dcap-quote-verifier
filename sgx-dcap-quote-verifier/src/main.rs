/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#![allow(unused)]

use std::mem;
use std::ptr;
use std::time::{Duration, SystemTime};

use clap::Parser;

use intel_tee_quote_verification_rs::*;
use intel_tee_quote_verification_sys as qvl_sys;

#[cfg(debug_assertions)]
const SGX_DEBUG_FLAG: i32 = 1;
#[cfg(not(debug_assertions))]
const SGX_DEBUG_FLAG: i32 = 0;

// C library bindings

#[link(name = "sgx_urts")]
extern "C" {
    fn sgx_create_enclave(
        file_name: *const u8,
        debug: i32,
        launch_token: *mut [u8; 1024usize],
        launch_token_updated: *mut i32,
        enclave_id: *mut u64,
        misc_attr: *mut qvl_sys::sgx_misc_attribute_t,
    ) -> u32;
    fn sgx_destroy_enclave(enclave_id: u64) -> u32;
}

/// Quote verification
///
/// # Param
/// - **quote**\
/// ECDSA quote buffer.
///
fn ecdsa_quote_verification(quote: &[u8]) {
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    // Untrusted quote verification

    // call DCAP quote verify library to get supplemental latest version and data size
    // version is a combination of major_version and minor version
    // you can set the major version in 'supp_data.major_version' to get old version supplemental data
    // only support major_version 3 right now
    //
    match tee_get_supplemental_data_version_and_size(quote) {
        Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                println!("\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.");
                println!("\tInfo: latest supplemental data major version: {}, minor version: {}, size: {}",
                         u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into().unwrap()),
                         u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into().unwrap()),
                         supp_size,
                     );
                supp_data_desc.data_size = supp_size;
            } else {
                println!("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => println!(
            "\tError: tee_get_quote_supplemental_data_size failed: {:#04x}",
            e as u32
        ),
    }

    // get collateral
    let collateral = tee_qv_get_collateral(quote);
    match collateral {
        Ok(ref c) => println!("\tInfo: tee_qv_get_collateral successfully returned."),
        Err(e) => println!("\tError: tee_qv_get_collateral failed: {:#04x}", e as u32),
    };

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    match tee_verify_quote(
        quote,
        collateral.ok().as_ref(),
        current_time,
        None,
        p_supplemental_data,
    ) {
        Ok((colla_exp_stat, qv_result)) => {
            collateral_expiration_status = colla_exp_stat;
            quote_verification_result = qv_result;
            println!("\tInfo: App: tee_verify_quote successfully returned.");
        }
        Err(e) => println!("\tError: App: tee_verify_quote failed: {:#04x}", e as u32),
    }

    // check verification result
    //
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if collateral_expiration_status == 0 {
                println!("\tInfo: App: Verification completed successfully.");
            } else {
                println!("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!(
                "\tWarning: App: Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED
        | _ => {
            println!(
                "\tError: App: Verification completed with Terminal result: {:x}",
                quote_verification_result as u32
            );
        }
    }

    // check supplemental data if necessary
    //
    if supp_data_desc.data_size > 0 {
        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        let version_s = unsafe { supp_data.__bindgen_anon_1.__bindgen_anon_1 };
        println!(
            "\tInfo: Supplemental data Major Version: {}",
            version_s.major_version
        );
        println!(
            "\tInfo: Supplemental data Minor Version: {}",
            version_s.minor_version
        );

        // print SA list if exist, SA list is supported from version 3.1
        //
        if unsafe { supp_data.__bindgen_anon_1.version } > 3 {
            let sa_list = unsafe { std::ffi::CStr::from_ptr(supp_data.sa_list.as_ptr()) };
            if sa_list.to_bytes().len() > 0 {
                println!("\tInfo: Advisory ID: {}", sa_list.to_str().unwrap());
            }
        }
    }
}

#[derive(Parser)]
struct Cli {
    /// Specify quote path
    #[arg(long = "quote")]
    quote_path: Option<String>,
}

fn main() {
    // Specify quote path from command line arguments
    //
    let args = Cli::parse();
    let default_quote = "quote.dat";
    let quote_path = args.quote_path.as_deref().unwrap_or(default_quote);

    //read quote from file
    //
    let quote = std::fs::read(quote_path).expect("Error: Unable to open quote file");

    println!("Info: ECDSA quote path: {}", quote_path);

    // We demonstrate two different types of quote verification
    //      a. Trusted quote verification - quote will be verified by Intel QvE
    //      b. Untrusted quote verification - quote will be verified by untrusted QVL (Quote Verification Library)
    //          this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    //

    // Untrusted quote verification, ignore error checking
    //
    println!("\nUntrusted quote verification:");
    ecdsa_quote_verification(&quote);

    println!();
}
