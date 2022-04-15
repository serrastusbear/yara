rule Industroyer2_Strings
{
	meta:
		description = "Identify strings associated with Industroyer2"
		authoir = "Joe Slowik"
		sha256 = "d69665f56ddef7ad4e71971f06432e59f1510a7194386e5f0e8926aea7b88e00"
	strings:
		$ms = "MSTR ->> SLV" fullword ascii
		$sm = "MSTR <<- SLV" fullword ascii
		$s1 = "Current operation : %s" fullword ascii
		$s2 = "Switch value: %s" fullword ascii
		$s3 = "Connection closed ..." fullword ascii
		$s4 = "PServiceControl.exe" fullword ascii
		$s5 = "Length:%u bytes | " ascii
		$s6 = "Sent=x%X | Received=x%X" ascii
		$s7 = "ASDU:%u | OA:%u | IOA:%u | " ascii
		$s8 = "Cause: %s (x%X) | Telegram type: %s (x%X)" ascii
		$s9 = "PService_PPD.exe" wide
		$s10 = "D:\\OIK\\DevCounter" wide
	condition:
		uint16(0) == 0x5a4d and #ms > 1 and #sm > 2 and 5 of ($s*)
}