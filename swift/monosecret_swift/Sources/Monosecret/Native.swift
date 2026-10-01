import CMonosecret
import Darwin
import Foundation

enum Native {
    static func resolve(_ requestJSON: String) throws -> String {
        guard let response = requestJSON.withCString({ monosecret_resolve($0) }) else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_resolve returned null"
            )
        }

        defer {
            monosecret_free(response)
        }

        guard let result = String(validatingUTF8: response) else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_resolve returned invalid UTF-8"
            )
        }

        return result
    }

    static func call(_ requestJSON: String) throws -> String {
        typealias CallFunction = @convention(c) (UnsafePointer<CChar>?)
            -> UnsafeMutablePointer<CChar>?

        // The checked-in package still downloads the 0.19.1 XCFramework. Look
        // up the 0.20+ entry point only when inline specs are used, so ordinary
        // calls continue to compile and run against that older binary.
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "monosecret_call") else {
            throw MonosecretError(
                kind: "capability",
                message: "the loaded monosecret_ffi library does not support inline specs "
                    + "(missing monosecret_call)"
            )
        }

        let call = unsafeBitCast(symbol, to: CallFunction.self)

        guard let response = requestJSON.withCString({ call($0) }) else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_call returned null"
            )
        }

        defer {
            monosecret_free(response)
        }

        guard let result = String(validatingUTF8: response) else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_call returned invalid UTF-8"
            )
        }

        return result
    }

    static func abiVersion() throws -> String {
        guard
            let pointer = monosecret_abi_version(),
            let version = String(validatingUTF8: pointer)
        else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_abi_version returned null or invalid UTF-8"
            )
        }

        return version
    }
}