######################################################################################################
# CC_Checker.ps1
#		Brute Forces the digits of a luhn valid CC number, then hashes and checks it against the hash
#
#		Input File Format - 4321??????1234:HASH
#
# Usage: Usage CC_Checker.ps1 -i INPUT_FILE -o OUTPUT_FILE -h HASH_TYPE [1-3]
#			1 = SHA1
#			2 = SHA256
#			3 = MD5
#
# Requirements:
#		-Preferred:
#			-First 6, Last 4, and hash of CC number
#				-File format:  123456??????1234:HASH
#		-Last 4 or missing first 4 (or more)
#			- A list of common IINs will be used to cut down on the guessing space
#		-Worst Case:
#				- ????????????????:HASH
#				- Brute force all digits
#				- This will be reduced by looking up the IINs and using them (change the file name near the end from IINs.txt)
#		-Also Powershell, but that should be obvious
#
# Written by Karl Fosaaen
#	Twitter: @kfosaaen
#
######################################################################################################

#Checks your ARGS
param (
    [string]$input_file = $(throw "-i input file is required`nUsage CC_Checker.ps1 -i INPUT_FILE -o OUTPUT_FILE -h HASH_TYPE"),
    [string]$output_file = $(throw "-o outputfile is required`nUsage CC_Checker.ps1 -i INPUT_FILE -o OUTPUT_FILE -h HASH_TYPE"),
    [int]$hash_type = $(throw "-h hashtype is required.`n`t1 = SHA1`n`t2 = SHA256`n`t3 = MD5`nUsage CC_Checker.ps1 -i INPUT_FILE -o OUTPUT_FILE -h HASH_TYPE")
 )


########################################################################################
##	            Returns true if the given array of digits represents 				  ##
##		 		      a valid Luhn number, and false otherwise.						  ##
## Adapted from http://scriptolog.blogspot.com/2008/01/powershell-luhn-validation.html##
########################################################################################
function Test-LuhnNumber([int[]]$digits){
     
    [int]$sum=0
    [bool]$alt=$false

    for($i = $digits.length - 1; $i -ge 0; $i--){
        if($alt){
            $digits[$i] *= 2
            if($digits[$i] -gt 9) { $digits[$i] -= 9 }
        }

        $sum += $digits[$i]
        $alt = !$alt
    }

    return ($sum % 10) -eq 0
}	

#Hashing and Comparing Operation (SHA1)
function SHA1-test-hash($toTest, $checkHash){
	#Hash Result
	$res=""

	#Cracked?
	$cracked=0
	
	#Hash Function
	$SHA1_hasher = new-object System.Security.Cryptography.SHA1Managed
	$toHash = [System.Text.Encoding]::UTF8.GetBytes($toTest)
	$hashByteArray = $SHA1_hasher.ComputeHash($toHash)
	foreach($byte in $hashByteArray)
	{
		$res += "{0:X2}" -f $byte
	}

	#Compare and write to file
	if ($checkHash -eq $res){
		#Echo out found CC Numbers to the screen
		Write-Host "`n`nFound SHA1:"$res"`nCardNumber: "$toTest
		$toWrite="CC_Number:"+$toTest+":Hash:"+$checkHash+""
		$toWrite | out-file -encoding ASCII -append $output_file
		$cracked=1
	}
	if ($cracked -eq 1){
		return 1
	}
	else {
		return 0
	}
}
#Hashing and Comparing Operation (SHA256)
function SHA256-test-hash($toTest, $checkHash){
	$result1 = ""
	$sha256_hasher = new-object -TypeName System.Security.Cryptography.SHA256Managed
	$utf8 = [System.Text.Encoding]::UTF8.GetBytes($toTest)
	$SHA256hash = $sha256_hasher.ComputeHash($utf8)

	foreach($byte in $SHA256hash)
	{
		$result1 += "{0:X2}" -f $byte
	}

	#Compare and write to file
	if ($checkHash -eq $result1){
		#Echo out found CC Numbers to the screen
		Write-Host "`n`nFound SHA256:"$result1"`nCardNumber: "$toTest
		$toWrite="CC_Number:"+$toTest+":Hash:"+$checkHash+""
		$toWrite | out-file -encoding ASCII -append $output_file
		$cracked=1
	}
	if ($cracked -eq 1){
		return 1
	}
	else {
		return 0
	}

}
#Hashing and Comparing Operation (MD5)
function MD5-test-hash($toTest, $checkHash){
	$result = ""
	$md5_hasher = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$utf8 = [System.Text.Encoding]::UTF8.GetBytes($toTest)
	$MD5hash = $md5_hasher.ComputeHash($utf8)
	foreach($byte in $MD5hash)
	{
		$result += "{0:X2}" -f $byte
	}
	#Compare and write to file
	if ($checkHash -eq $result){
		#Echo out found CC Numbers to the screen
		Write-Host "`n`nFound MD5:"$result"`nCardNumber: "$toTest
		$toWrite="CC_Number:"+$toTest+":Hash:"+$checkHash+""
		$toWrite | out-file -encoding ASCII -append $output_file
		$cracked=1
	}
	if ($cracked -eq 1){
		return 1
	}
	else {
		return 0
	}
}

function brute-force($guess_static){
#Iterate through the numbers - I'm aware that this is ugly
	while (1){
		#Set Static Values for valid IIN prefixes
		for($a=0;$a -le 9; $a++){
			#If the place value is 10, then bruteforce that place, otherwise set static value
			if($guess_static[0] -ne 10){$a = $guess_static[0]; $is_static_a="true"}
			else{$is_static_a="false"}
			
			for($b=0;$b -le 9; $b++){
				if($guess_static[1] -ne 10){$b = $guess_static[1]; $is_static_b="true"}
				else{$is_static_b="false"}
				
				for($c=0;$c -le 9; $c++){
					if($guess_static[2] -ne 10){$c = $guess_static[2]; $is_static_c="true"}
					else{$is_static_c="false"}
					
					for($d=0;$d -le 9; $d++){
						if($guess_static[3] -ne 10){$d = $guess_static[3]; $is_static_d="true"}
						else{$is_static_d="false"}
						
						for($e=0;$e -le 9; $e++){
							if($guess_static[4] -ne 10){$e = $guess_static[4]; $is_static_e="true"}
							else{$is_static_e="false"}
							
							for($f=0;$f -le 9; $f++){
								if($guess_static[5] -ne 10){$f = $guess_static[5]; $is_static_f="true"}
								else{$is_static_f="false"}
								
								for($g=0;$g -le 9; $g++){
									if($guess_static[6] -ne 10){$g = $guess_static[6]; $is_static_g="true"}
									else{$is_static_g="false"}
									
									for($h=0;$h -le 9; $h++){
										if($guess_static[7] -ne 10){$h = $guess_static[7]; $is_static_h="true"}
										else{$is_static_h="false"}
										
										for($i=0;$i -le 9; $i++){
											if($guess_static[8] -ne 10){$i = $guess_static[8]; $is_static_i="true"}
											else{$is_static_i="false"}
											
											for($j=0;$j -le 9; $j++){
												if($guess_static[9] -ne 10){$j = $guess_static[9]; $is_static_j="true"}
												else{$is_static_j="false"}
												
												for($k=0;$k -le 9; $k++){
													if($guess_static[10] -ne 10){$k = $guess_static[10]; $is_static_k="true"}
													else{$is_static_k="false"}

													for($l=0;$l -le 9; $l++){
														if($guess_static[11] -ne 10){$l = $guess_static[11]; $is_static_l="true"}
														else{$is_static_l="false"}
														
														for($m=0;$m -le 9; $m++){
															if($guess_static[12] -ne 10){$m = $guess_static[12]; $is_static_m="true"}
															else{$is_static_m="false"}
															
															for($n=0;$n -le 9; $n++){
																if($guess_static[13] -ne 10){$n = $guess_static[13]; $is_static_n="true"}
																else{$is_static_n="false"}
																
																for($o=0;$o -le 9; $o++){
																	if($guess_static[14] -ne 10){$o = $guess_static[14]; $is_static_o="true"}
																	else{$is_static_o="false"}
																	
																	for($p=0;$p -le 9; $p++){
																		if($guess_static[15] -ne 10){$p = $guess_static[15]; $is_static_p="true"}
																		else{$is_static_p="false"}
																		
																		#Allows for 15 and 16 digit cards
																		if($first6_full.length -eq 15){$guess = $a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n,$o}
																		else{$guess = $a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n,$o,$p}
																		
																		#Test the number for Luhn pass and then check hash
																		if (Test-LuhnNumber($guess)){
																			$guessJoined = -join $guess
																			#Write-Host "Valid Luhn: "$guessJoined"`n"
																			Write-Host -NoNewline "."
																			
																			#And check for hash type here.
																			if($hash_type -eq 1){
																				if(SHA1-test-hash $guessJoined $src_hash){
																					$breaker="false"
																					return " "
																				}
																			}
																			elseif($hash_type -eq 2){
																				if(SHA256-test-hash $guessJoined $src_hash){
																					$breaker="false"
																					return " "
																				}																			
																			}
																			else{
																				if(MD5-test-hash $guessJoined $src_hash){
																					$breaker="false"
																					return " "
																				}
																			}
																		}
																		if($breaker -eq "false"){break}															
																		if($is_static_p -eq "true"){break}
																	}
																	if($breaker -eq "false"){break}
																	if($is_static_o -eq "true"){break}
																}
																if($breaker -eq "false"){break}
																if($is_static_n -eq "true"){break}
															}
															if($breaker -eq "false"){break}
															if($is_static_m -eq "true"){break}
														}
														if($breaker -eq "false"){break}
														if($is_static_l -eq "true"){break}
													}
													if($breaker -eq "false"){break}
													if($is_static_k -eq "true"){break}
												}
												if($breaker -eq "false"){break}
												if($is_static_j -eq "true"){break}
											}
											if($breaker -eq "false"){break}
											if($is_static_i -eq "true"){break}
										}
										if($breaker -eq "false"){break}
										if($is_static_h -eq "true"){break}
									}
									if($breaker -eq "false"){break}
									if($is_static_g -eq "true"){break}
								}
								if($breaker -eq "false"){break}
								if($is_static_f -eq "true"){break}
							}
							if($breaker -eq "false"){break}
							if($is_static_e -eq "true"){break}
						}
						if($breaker -eq "false"){break}
						if($is_static_d -eq "true"){break}
					}
					if($breaker -eq "false"){break}
					if($is_static_c -eq "true"){break}
				}
				if($breaker -eq "false"){break}
				if($is_static_b -eq "true"){break}
			}
			if($breaker -eq "false"){break}
			if($is_static_a -eq "true"){break}
		}
	break
	}
}


Get-Content $input_file | Foreach-Object {

	#Reads the input
	$first6_full=$_.Split(“:”)[0]
	$src_hash=$_.Split(“:”)[1]
	
	if($first6_full.length -eq 14){$toguess=0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	elseif($first6_full.length -eq 15){$toguess=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	else{$toguess=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	
	#Reads digits to array
	for($z=0;$z -le $first6_full.length-1; $z++){
		if($first6_full[$z] -eq "?"){
			$toguess[$z]="10"
		}
		else{
			$toguess[$z]=[int]"$($first6_full[$z])"
		}
	}

	$breaker="true"
	
	Write-Host -NoNewline "`nTesting "$first6_full"`n"

	#Card type detection
	if($toguess[0] -ne 10){
		switch ($toguess[0]) 
		{ 
			0 {"Card Type: ISO/TC 68 Assigned Card"}
			1 {"Card Type: Airline Card"} 
			2 {"Card Type: Airline Card"} 
			3 {"Card Type: Diners, AMEX, or JCB Card"} 
			4 {"Card Type: Visa Card"} 
			5 {"Card Type: MasterCard"} 
			6 {"Card Type: Retailer, Discover, or Bank Card"} 
			7 {"Card Type: Petroleum Card"}
			8 {"Card Type: Healthcare, Telecom, or other industry Card"} 
			9 {"Card Type: National Banking Card"}
		}
	}

	$toguess_static=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	for($ab=0;$ab -le 15; $ab++){$toguess_static[$ab]=$toguess[$ab]}
	
	Write-Host -NoNewline "..."
	
	
	#############################################
	#											#
	#	Change this line to your BIN/IIN file	#
	#											#
	$IIN_file = "IINS.txt"
	#											#
	#############################################
				
	#Check here for if the first four are blank (covers if first four or more are missing)
	if (($toguess[0] -eq 10) -and ($toguess[1] -eq 10) -and ($toguess[2] -eq 10) -and ($toguess[3] -eq 10)){
	
		#This is the hackish way to get around the "break/continue" dilema in Foreach-Object loops
		While($breaker -eq "true"){
			Get-Content $IIN_file | Foreach-Object {
	
				#Write-host "`n`nCurrent IIN:"$_"`n"
				
				#Resets the IIN from previous round to the static input
				$toguess=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
				for($abc=0;$abc -le 15; $abc++){$toguess[$abc]=$toguess_static[$abc]}
				
				$input_length = $_.length
			
				for($y=0;$y -le $input_length-1; $y++){$toguess[$y]=[int]"$($_[$y])"}
				
				#If this is found, then break the get-content loop
				if(brute-force($toguess)){
					$breaker="false"
					continue
				}
				$breaker="false"
			}
			
		}
	}
	
	brute-force($toguess)

}
Write-Host "`nDone`n"



