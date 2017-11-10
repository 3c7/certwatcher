rule Paypal_phishing {
    meta:
        description = "Detects paypal phishing domains"
        author = "Nils Kuhnert"
        color = "red"
    strings:
        $s0 = "-paypal.com"
        $s1 = ".paypal.com."
    condition:
        $s0 or $s1
}
