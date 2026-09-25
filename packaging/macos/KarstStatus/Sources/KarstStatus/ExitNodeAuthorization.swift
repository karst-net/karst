// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import Foundation
import Security

/// An administrator's authorization for one exit-node change (ADR-0036 §3).
///
/// Acquired here, in the logged-in user's session, where the system can show
/// its own credential dialog; checked again by the extension, as root, from
/// the external form this carries (`KarstPacketTunnel`'s `ExitConsent`). The
/// app's own success is never taken on trust.
///
/// Must outlive the provider message it accompanies: the external form names
/// this authorization instance, so `invalidate()` only once the extension has
/// answered.
final class ExitNodeAuthorization {
    /// The right the package defines — `KarstPacketTunnel`'s
    /// `ExitConsent.rightName`, duplicated because the two targets share no
    /// code.
    static let rightName = "dev.karst.exit-node.consent"

    enum Failure: LocalizedError {
        case cancelled
        case denied
        case failed(OSStatus)

        var errorDescription: String? {
            switch self {
            case .cancelled: return nil
            case .denied: return "Changing the exit node needs an administrator of this Mac."
            case .failed(let status): return "Could not obtain authorization (OSStatus \(status))."
            }
        }
    }

    private let reference: AuthorizationRef
    /// Base64 of the `AuthorizationExternalForm` sent to the extension.
    let externalForm: String

    private init(reference: AuthorizationRef, externalForm: String) {
        self.reference = reference
        self.externalForm = externalForm
    }

    /// Show the system's administrator dialog for `rightName` and, on
    /// success, return an authorization the extension can verify.
    static func request() -> Result<ExitNodeAuthorization, Failure> {
        var created: AuthorizationRef?
        var status = AuthorizationCreate(nil, nil, [], &created)
        guard status == errAuthorizationSuccess, let reference = created else {
            return .failure(.failed(status))
        }

        status = rightName.withCString { name -> OSStatus in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer -> OSStatus in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(
                    reference, &rights, nil,
                    [.interactionAllowed, .extendRights, .preAuthorize], nil
                )
            }
        }
        switch status {
        case errAuthorizationSuccess:
            break
        case errAuthorizationCanceled:
            AuthorizationFree(reference, [])
            return .failure(.cancelled)
        case errAuthorizationDenied:
            AuthorizationFree(reference, [])
            return .failure(.denied)
        default:
            AuthorizationFree(reference, [])
            return .failure(.failed(status))
        }

        var form = AuthorizationExternalForm()
        status = AuthorizationMakeExternalForm(reference, &form)
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(reference, [.destroyRights])
            return .failure(.failed(status))
        }
        let encoded = withUnsafeBytes(of: &form) { Data($0) }.base64EncodedString()
        return .success(ExitNodeAuthorization(reference: reference, externalForm: encoded))
    }

    /// Release the authorization and destroy its acquired rights, so the
    /// token cannot be replayed once its one request is answered.
    func invalidate() {
        AuthorizationFree(reference, [.destroyRights])
    }
}
