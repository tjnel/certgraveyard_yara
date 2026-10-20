import "pe"

rule MAL_Compromised_Cert_MeshAgent_SSL_com_A9FF55228926F50BD47C72A9CFFA41D {
   meta:
      description         = "Detects MeshAgent with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-24"
      version             = "1.0"

      hash                = "76f4053fc0d639591b809faf3d9bdc5758dcdabe8fc4a07ae87008988fbcee81"
      malware             = "MeshAgent"
      malware_type        = "Remote access tool"
      malware_notes       = "https://rogueauthority.org/signed-werkstatt-agent-fake-lock-screen"

      signer              = "ALI YILDIZ"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "a9:ff:55:22:89:26:f5:0b:d4:7c:72:a9:cf:fa:41:d"
      cert_thumbprint     = "798f0005b7da9ec4cab69996991d249db4a2b7c0"
      cert_valid_from     = "2026-02-24"
      cert_valid_to       = "2027-02-23"

      country             = "IT"
      state               = "Napoli"
      locality            = "Afragola"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "a9:ff:55:22:89:26:f5:0b:d4:7c:72:a9:cf:fa:41:d"
      )
}
