# yara-binary-code-analysis
Binary code analysis with IDA Pro and Yara.

Malware samples downloaded from: https://drive.google.com/open?id=1yG4mu-xNYva86VfukJZULisA8bqtHZMY

The signature is based mainly on these two files -

VirusShare_4d75cc6649b3e94c32fb4be6b4f4536f
VirusShare_7f9fb03c47c97c6740883dcf70f3ad32

I have written at least one string of each of the following string types:
1. Static binary data (so, no wildcards)
2. Binary data containing wild cards (? and ??)
3. Binary data containing ranges (using the [] and numbers)
4. Binary data containing byte alternatives ( 45 | 46 | 67 | … | )

The signature meets the following criterion
1. All strings must match at least one place in 2 or more of the malware samples from your group identified in HW02 
2. The strings must not match on any legitimate windows binaries
