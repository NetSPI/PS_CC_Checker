CC_Checker
==========
CC_Checker cracks credit card hashes with PowerShell.

CC_Checker.ps1
	Brute Forces the digits of a luhn valid CC number, then hashes and checks it against the hash
	Input File Format - 4321??????1234:HASH
	
	Use ? for the digits that are unknown

Usage: Usage CC_Checker.ps1 -i INPUT_FILE -o OUTPUT_FILE -h HASH_TYPE [1-3]
			1 = SHA1
			2 = SHA256
			3 = MD5

Requirements:
	-Preferred:
		-First 6, Last 4, and hash of CC number
			-File format:  123456??????1234:HASH
	-Last 4 or missing first 4 (or more)
		- A list of common IINs will be used to cut down on the guessing space
		-Worst Case:
			- ????????????????:HASH
			- Brute force all digits
			- This will be reduced by looking up the IINs and using them
				-If you are using this use case, then change the file name on line 349
	-Also Powershell, but that should be obvious

To Add:
	- Card type detection (VISA, MC, Diners, etc.)
		-Overall Length, middle digits needed to brute force (based off of card type, currently done manually with ?s)

	- More hashing algorithms
		
	- Add Salt options

	
	
#						  #
# Written by Karl Fosaaen #
#	Twitter: @kfosaaen 	  #
#						  #