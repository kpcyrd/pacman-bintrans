table! {
    pkgs (id) {
        id -> Integer,
        sha256sum -> Text,
        filename -> Text,
        signature -> Text,
        uuid -> Nullable<Text>,
    }
}
