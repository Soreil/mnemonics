/*Package mnemonics makes textual representations out of IP adresses

Algoritm description:
Check of the IP is valid IPv4 or IPv6

Append the salt to the IP
SHA1 the IP
Split the SHA 1 in to 4 chunks of 5 bytes

For every chunk of 5 bytes take the first 4 bytes

Convert the 4 bytes to a hex representation
Convert the hex representation to a uint32

mod the uint32 by 256 and devide that by 16
Use this result as an index for the Mnemonic start array
Append the array index's value to the output result

mod the uint32 by 16
Use this result as an index for the Mnemonic end array
Append the array index's value to the output result

This will give you 8 appends in total the resulting array is your output
*/
package mnemonic
