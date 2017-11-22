// This is the certwatcher std ruleset
// The color attribute is currently not usable

rule Paypal_phishing {
    meta:
        description = "Detects possible paypal phishing domains"
        author = "Nils Kuhnert"
        color = "red"
    strings:
        $s0 = "-paypal.com"
        $s1 = ".paypal.com."
        $s2 = "-paypal-"
    condition:
        1 of them
}

rule Apple_phishing {
    meta:
        description = "Detects possible apple phishing domains"
        author = "Nils Kuhnert"
        color = "red"
    strings:
        $s0 = "-apple.com"
        $s1 = "apple.com."
        $s2 = "apple-com"
    condition:
        1 of them
}

rule Google_phishing {
    meta:
        description = "Detects possible google phishing domains"
        author = "Nils Kuhnert"
        color = "red"
    strings:
        $s0 = "-google.com"
        $s1 = ".google."
        $s2 = "google-com"
        $s3 = "-google.de"
        $s4 = "google-de"
        $s5 = "gmail"
        $s6 = "googlemail"
        $s7 = "google-mail"
    condition:
        1 of them
}

rule Webde_phishing {
    meta:
        description = "Detects possible web.de phishing domains"
        author = "Nils Kuhnert"
        color = "yellow"
    strings:
        $s0 = "-web.de"
        $s1 = ".web.de." // Too generic?
        $s2 = "web-de" // Too generic?
    condition:
        1 of them
}

rule Gmx_phishing {
    meta:
        description = "Detects possible gmx.de/.net phishing domains"
        author = "Nils Kuhnert"
        color = "yellow"
    strings:
        $s0 = "-gmx.de"
        $s1 = "-gmx.net"
        $s2 = ".gmx.de."
        $s3 = ".gmx.net."
        $s4 = "gmx-de"
        $s5 = "gmx-net"
    condition:
        1 of them
}

