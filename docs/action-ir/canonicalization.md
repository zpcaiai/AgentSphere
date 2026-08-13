# Action canonicalization

Input is parsed by a duplicate-key-aware bounded visitor before Serde conversion. Controlled identifiers are trimmed and case-normalized; Unicode resource locators use NFC. File-like locators are normalized lexically and reject `..`; HTTP locators reject embedded credentials. Times are UTC with millisecond precision. Maps are serialized with RFC 8785-compatible JCS. No permission-expanding defaults are inserted.

