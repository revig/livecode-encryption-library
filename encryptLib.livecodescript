script "encryptLib"

--==================================================================--
--
-- encryptLib
--
-- library of encryption handlers and functions based on revIgniter 2.1.7
--
-- ¬¨¬©2020 revIgniter.com
--
-- Version 1.0.0
--
-- License: Apache 2.0
--
--==================================================================--




--> Library
--==================================================================--
--
-- Start using/Stop using
--

on libraryStack
   if the short name of the target = the short name of me then
      -- Put initialization stuff here:
      _rigSetDefaultValues

      if the environment is "development" then
         answer the target & " got libraryStack message"
      end if
      --
   else
      pass libraryStack
   end if
end libraryStack


on releaseStack
   if the short name of the target = the short name of me then
      -- Put cleanup stuff here:

      if the environment is "development" then
         answer the target & " got releaseStack message"
      end if
      --
   else
      pass releaseStack
   end if
end releaseStack


--==================================================================--
--
-- Main Stuff
--

--> Declarations

local sEncryptA



--> Handler



/*----------------------------------------------------------------------
--| COMMAND rigEncryptErrorHandling
--|
--| Author: rabit
--| Version:  1.1
--| Created: 2019-08-02
--| Last Mod: 2020-08-03
--| Requires: --
--|
--| Summary: Save or display errors. Calls an optional error handling handler (log)
--|          which is not included!
--|
--| Format:  rigEncryptErrorHandling param1, [param2]
--|
--| Parameters: string <pError>, bool <pExit> (optional)
--|
--| Return: empty
----------------------------------------------------------------------*/

command rigEncryptErrorHandling pError pExit
   try
      log pError
   catch e
      answer error pError
   end try

   if pExit is TRUE then
      exit to top
   end if
end rigEncryptErrorHandling




/*----------------------------------------------------------------------
--| COMMAND _rigSetDefaultValues
--|
--| Author: rabit
--| Version:  1.0
--| Created: 2019-01-04
--| Last Mod: 2019-01-04
--| Requires: --
--|
--| Summary: Set default values for library variables.
--|
--| Format:  _rigSetDefaultValues
--|
--| Parameters: --
--|
--| Return: empty
----------------------------------------------------------------------*/

private command _rigSetDefaultValues
   put "SHA-1" into sEncryptA["_hashType"]
   put "bf" into sEncryptA["cipher"]
   put 128 into sEncryptA["cipherKeyLength"]
end _rigSetDefaultValues





/*----------------------------------------------------------------------
--| FUNCTION _rigGetEncryptionKey
--|
--| Author: rabit
--| Version:  1.2
--| Created: 2009-10-16
--| Last Mod: 2020-08-04
--| Requires: rigEncryptErrorHandling, rigHexDigest()
--|
--| Summary: Fetch the encryption key. Returns it as md5 or SHA3-256 (depending on LC version)
--|          in text format as a 32 (64) digit hexadecimal number.
--|
--| Format:  _rigGetEncryptionKey([param1])
--|
--| Parameters: string <pKey> (optional)
--|
--| Return: string
----------------------------------------------------------------------*/

private function _rigGetEncryptionKey pKey
   if pKey is empty then
      if sEncryptA["encryptionKey"] is not empty then
         # RETURN KEY SET USING rigSetEncryptionKey
         return sEncryptA["encryptionKey"]
      end if

      --------------- desktop / mobile
      ask question "Please enter your encryption key."
      put it into pKey
      -- put rigFetchConfigItem("encryption_key") into pKey
      ---------------
      if pKey is empty then
         -- rigShowError "In order to use the Encrypt library requires that you set an encryption key in your config file." --------------- desktop / mobile
         # ERROR, EXIT TO TOP
         rigEncryptErrorHandling "In order to use the Encrypt library you need to provide an encryption key.", TRUE
         --------------- desktop / mobile
      else
         put pKey into sEncryptA["encryptionKey"]
         ---------------
      end if
   end if

   put textEncode(pKey, "UTF-8") into pKey

   return rigHexDigest(pKey)
end _rigGetEncryptionKey










/*----------------------------------------------------------------------
--| COMMAND rigSetEncryptionKey
--|
--| Author: rabit
--| Version:  1.1
--| Created: 2009-10-16
--| Last Mod: 2020-08-04
--| Requires: rigHexDigest(), rigEncryptErrorHandling
--|
--| Summary: Set the encryption key. Undocumented!!!!!!!!!!!
--|
--| Format:  rigSetEncryptionKey param1
--|
--| Parameters: string <pKey>
--|
--| Return: empty
----------------------------------------------------------------------*/

command rigSetEncryptionKey pKey
   --------------- desktop / mobile
   -- put pKey into sEncryptA["encryptionKey"]
   if pKey <> empty then
      put textEncode(pKey, "UTF-8") into pKey
      put rigHexDigest(pKey) into sEncryptA["encryptionKey"]
   else
      rigEncryptErrorHandling "No key provided!"
   end if
   ---------------
end rigSetEncryptionKey










/*----------------------------------------------------------------------
--| FUNCTION rigEncode
--|
--| Author: rabit
--| Version:  2.1
--| Created: 2009-10-16
--| Last Mod: 2020-08-03
--| Requires: _rigGetEncryptionKey(), _rigXorEncode(), rigEncryptErrorHandling
--|
--| Summary: Encodes the message string using bitwise XOR encoding.
--|          The key is combined with a random hash, and then it
--|          too gets converted using XOR. The whole thing is then
--|          encrypted using a randomly generated salt for the key.
--|          The end result is a message string that is randomized with
--|          each call to this function, even if the supplied message and
--|          key are the same.
--|
--| Format:  rigEncode(param1, param2)
--|
--| Parameters: string <pString> the string to encode, string <pKey>
--|
--| Return: string
----------------------------------------------------------------------*/

function rigEncode pString pKey
   local tKey, tEnc

   put _rigGetEncryptionKey(pKey) into tKey
   put _rigXorEncode(pString, tKey) into tEnc

   --------------- desktop / mobile
   if sEncryptA["cipher"] is empty then
      # ERROR, EXIT TO TOP
      rigEncryptErrorHandling "In order to use the Encrypt library you need to provide a cipher.", TRUE
   end if
   -----------------------

   encrypt tEnc using sEncryptA["cipher"] with tKey at sEncryptA["cipherKeyLength"] bit
   if the result is empty then
      return base64encode(it)
   end if

   return FALSE
end rigEncode









/*----------------------------------------------------------------------
--| FUNCTION rigDecode
--|
--| Author: rabit
--| Version: 2.2
--| Created: 2009-10-16
--| Last Mod: 2014-12-22
--| Requires: _rigGetEncryptionKey(), _rigXorDecode()
--|
--| Summary: Reverses the above process.
--|
--| Format:  rigDecode(param1, param2)
--|
--| Parameters: string <pString> the string to decode, string <pKey>
--|
--| Return: string
----------------------------------------------------------------------*/

function rigDecode pString pKey
   local tKey, tRegEx, tDec

   put _rigGetEncryptionKey(pKey) into tKey
   -- put "[^a-zA-Z0-9\/\+=]" into tRegEx
   put "[^a-zA-Z0-9\/\+=" & numToNativeChar(10) & numToNativeChar(13) & "]" into tRegEx

   if matchtext(pString,tRegEx) is TRUE then
      return FALSE
   end if

   put base64Decode(pString) into tDec

   decrypt tDec using sEncryptA["cipher"] with tKey at sEncryptA["cipherKeyLength"] bit
   if the result is empty then
      return _rigXorDecode(it, tKey)
   end if

   return FALSE
end rigDecode









/*----------------------------------------------------------------------
--| FUNCTION _rigXorEncode
--|
--| Author: rabit
--| Version:  1.3
--| Created: 2009-10-16
--| Last Mod: 2014-12-23
--| Requires: rigRandomNum(), _rigHash(), rigSubstr(), _rigXorMerge()
--|
--| Summary: Takes a plain-text string and key as input and generates an
--|          encoded bit-string using XOR.
--|
--| Format:  _rigXorEncode(param1, param2)
--|
--| Parameters: string <pString>, string <pKey>
--|
--| Return: string
----------------------------------------------------------------------*/

private function _rigXorEncode pString pKey
   local tRand, tStringLength, tRandLength, tEnc

   put rigRandomNum() into tRand

   put _rigHash(tRand) into tRand

   put length(pString) into tStringLength
   put length(tRand) into tRandLength

   repeat with i = 1 to tStringLength
      put rigSubstr(tRand, ((i - 1) mod tRandLength) + 1, 1) & (numToNativeChar(rigSubstrToNum(tRand, ((i - 1) mod tRandLength) + 1, 1, TRUE) bitXOr rigSubstrToNum(pString, i, 1, TRUE))) after tEnc
   end repeat

   return _rigXorMerge(tEnc, pKey)
end _rigXorEncode







/*----------------------------------------------------------------------
--| FUNCTION _rigXorDecode
--|
--| Author: rabit
--| Version:  1.2
--| Created: 2009-10-16
--| Last Mod: 2014-12-23
--| Requires: _rigXorMerge(), rigSubstrToNum()
--|
--| Summary: Takes an encoded string and key as input and generates the
--|          plain-text original message.
--|
--| Format:  _rigXorDecode(param1, param2)
--|
--| Parameters: string <pString>, string <pKey>
--|
--| Return: string
----------------------------------------------------------------------*/

private function _rigXorDecode pString pKey
   local tString, tStringLength, tDec, i, j

   put _rigXorMerge(pString, pKey) into tString

   put length(tString) into tStringLength

   repeat with i = 1 to tStringLength
      put i into j
      add 1 to i
      put numToNativeChar((rigSubstrToNum(tString, i, 1, TRUE)) bitXOr (rigSubstrToNum(tString, j, 1, TRUE))) after tDec
   end repeat

   return tDec
end _rigXorDecode







/*----------------------------------------------------------------------
--| FUNCTION _rigXorMerge
--|
--| Author: rabit
--| Version:  1.3
--| Created: 2009-10-16
--| Last Mod: 2014-12-23
--| Requires: _rigHash(), rigSubstrToNum()
--|
--| Summary: Takes a string and key as input and computes the difference using XOR.
--|
--| Format:  _rigXorMerge(param1, param2)
--|
--| Parameters: string <pString>, string <pKey>
--|
--| Return: string
----------------------------------------------------------------------*/

private function _rigXorMerge pString pKey
   local tHash, tStringLength, tHashLength, i, tStr

   put _rigHash(pKey) into tHash

   put length(pString) into tStringLength
   put length(tHash) into tHashLength

   repeat with i = 1 to tStringLength
      put numToNativeChar((rigSubstrToNum(pString, i, 1, TRUE)) bitXOr (rigSubstrToNum(tHash, ((i - 1) mod tHashLength) + 1, 1, TRUE))) after tStr
   end repeat

   return tStr
end _rigXorMerge




/*----------------------------------------------------------------------
--| COMMAND rigSetCipher
--|
--| Author: rabit
--| Version:  1.0
--| Created: 2011-07-08
--| Last Mod: --
--| Requires: --
--|
--| Summary: Set the cipher and the key length
--|
--| Format:  rigSetCipher param1, param2
--|
--| Parameters: string <pName>, ineger <pKeyLength>
--|
--| Return: empty
----------------------------------------------------------------------*/

command rigSetCipher pName pKeyLength
   put pName into sEncryptA["cipher"]
   put pKeyLength into sEncryptA["cipherKeyLength"]
end rigSetCipher





/*----------------------------------------------------------------------
--| COMMAND rigSetHash
--|
--| Author: rabit
--| Version:  2.2
--| Created: 2009-10-16
--| Last Mod: 2018-11-02
--| Requires: --
--|
--| Summary: Set the hash type.
--|
--| Format:  rigSetHash [param1]
--|
--| Parameters: string <pType> (optional)
--|
--| Return: empty
----------------------------------------------------------------------*/

command rigSetHash pType
   local tType

   if (pType is empty) or (pType is not among the items of "SHA-1,SHA-224,SHA-256,SHA-384,SHA-512,SHA3-224,SHA3-256,SHA3-384,SHA3-512") then
      # DEFAULT HASH TYPE -- used for backwards compatibility
      put "SHA-1" into tType
   else
      put pType into tType
   end if

   set the itemdel to "."

   if (item 1 of the version < 9) then
      if (tType is not "SHA-1") and (tType is not "md5") then
         put "SHA-1" into sEncryptA["_hashType"]
      else
         put tType into sEncryptA["_hashType"]
      end if

   else
      # LC VERSION 9_0_0_dp_7 AND UP
      put tType into sEncryptA["_hashType"]
   end if
end rigSetHash








/*----------------------------------------------------------------------
--| FUNCTION _rigHash
--|
--| Author: rabit
--| Version:  2.3
--| Created: 2009-10-16
--| Last Mod: 2020-08-03
--| Requires: rigHexDigest()
--|
--| Summary: Hash encode a string.
--|
--| Format:  _rigHash(param1)
--|
--| Parameters: string <pStr>
--|
--| Return: string
----------------------------------------------------------------------*/

private function _rigHash pStr
   local tHash

   if sEncryptA["_hashType"] is empty then
      rigSetHash
   end if

   set the itemdel to "."

   if (item 1 of the version < 9) then
      if sEncryptA["_hashType"] is "SHA-1" then
         put sha1Digest(pStr) into tHash
      else

         put rigHexDigest(pStr) into tHash
      end if

   else
      # LC VERSION 9_0_0_dp_7 AND UP
      put messageDigest(pStr, sEncryptA["_hashType"]) into tHash
   end if

   return tHash
end _rigHash






/*----------------------------------------------------------------------
--| FUNCTION rigEncryptGet
--|
--| Author: rabit
--| Version:  1.0
--| Created: 2019-01-04
--| Last Mod: 2019-01-04
--| Requires: --
--|
--| Summary: Get library array variable values.
--|
--| Format:  rigEncryptGet(param)
--|
--| Parameters: string <pWhat>
--|
--| Return: mixed
----------------------------------------------------------------------*/

function rigEncryptGet pWhat
   if pWhat is among the keys of sEncryptA then
      return sEncryptA[pWhat]
   end if

   return empty
end rigEncryptGet





/*----------------------------------------------------------------------
--| COMMAND rigEncryptSet
--|
--| Author: rabit
--| Version:  1.0
--| Created: 2019-01-04
--| Last Mod: 2019-01-04
--| Requires: --
--|
--| Summary: Setter for encrypt array variables.
--|
--| Format:  rigEncryptSet param1, param2
--|
--| Parameters: string <pKey> sEncryptA array key, mixed <pVal>
--|
--| Return: empty
----------------------------------------------------------------------*/

command rigEncryptSet pKey pVal
   if pKey is among the keys of sEncryptA then
      put pVal into sEncryptA[pKey]
   end if
end rigEncryptSet





## ----------------------- revIgniter Common-livecodescript ---------------------------





/*----------------------------------------------------------------------
--| FUNCTION rigHexDigest
--|
--| Author: Dave Cragg
--| Modification: rabit
--| Version:  1.1
--| Created:  --
--| Last Mod: 2019-01-05
--| Requires: --
--|
--| Summary: This will convert the 128-bit value that md5digest() returns, or the 256-bit
--|          value that SHA3-256 returns to a hex format (a string with 32 / 64 characters)
--|          similiar to that returned by PHP and other languages.
--|
--| Format:  rigHexDigest(param1)
--|
--| Parameters: string <pStr>
--|
--| Return: string
----------------------------------------------------------------------*/

function rigHexDigest pStr
   local tDigestStr, tBinDecodetDigestStr

   set the itemDel to "."

   if item 1 of the version < 9 then
      put md5digest(pStr) into tDigestStr
   else
      put messageDigest(pStr, "SHA3-256") into tDigestStr
   end if

   get binarydecode("H*",tDigestStr,tBinDecodetDigestStr)

   return tBinDecodetDigestStr
end rigHexDigest






/*----------------------------------------------------------------------
--| FUNCTION rigRandomNum
--|
--| Author: rabit
--| Version:  1.2
--| Created: 2009-10-14
--| Last Mod: 2014-03-21
--| Requires: --
--|
--| Summary: Get the random number used for encryption and to build a session id.
--|
--| Format:  rigRandomNum()
--|
--| Parameters: --
--|
--| Return: empty
----------------------------------------------------------------------*/

function rigRandomNum
   local tRandomNum, tCounter, tSeed, tUpperLimit, tLowerLimit

   put "" into tRandomNum

   put 2147483647 into tUpperLimit
   put 0 into tLowerLimit

   put 1 into tCounter

   repeat while (the length of tRandomNum) < 32
      put (char -8 to -1 of the millisecs) + tCounter into tSeed
      set the randomSeed to tSeed

      put random(tUpperLimit - tLowerLimit + 1) + tLowerLimit -1 after tRandomNum

      add 1 to tCounter
   end repeat

   return tRandomNum
end rigRandomNum





/*----------------------------------------------------------------------
--| FUNCTION rigSubstr
--|
--| Author: rabit
--| Version:  1.1
--| Created: 2009-10-16
--| Last Mod: 2014-03-21
--| Requires: --
--|
--| Summary: Return part of a string.
--|
--| Format:  rigSubstr(param1, param2, param3)
--|
--| Parameters: string <pString>, integer <pStart>, integer <pLength>
--|
--| Return: empty
----------------------------------------------------------------------*/

function rigSubstr pString pStart pLength
   local tLastChar

   put pStart + (pLength - 1) into tLastChar
   return char pStart to tLastChar of pString
end rigSubstr









/*----------------------------------------------------------------------
--| FUNCTION rigSubstrToNum
--|
--| Author: rabit
--| Version:  1.2
--| Created: 2009-10-16
--| Last Mod: 2014-12-23
--| Requires: --
--|
--| Summary: Return part of a string as ascii values.
--|
--| Format:  rigSubstrToNum(param1, param2, param3, param4)
--|
--| Parameters: string <pString>, integer <pStart>, integer <pLength>, bool <pNative>
--|
--| Return: string
----------------------------------------------------------------------*/

function rigSubstrToNum pString pStart pLength pNative
   local tLastChar, tStr, tSubstr

   put pStart + (pLength - 1) into tLastChar
   put char pStart to tLastChar of pString into tStr

   repeat for each char thisChar in tStr
      if pNative then
         put nativeCharToNum(thisChar) after tSubstr
      else
         put codepointToNum(thisChar) after tSubstr
      end if
   end repeat

   return tSubstr
end rigSubstrToNum






--| END OF Encrypt.livecodescript
--| Location:  ./system/libraries/Encrypt.livecodescript
----------------------------------------------------------------------
