# TypeInfoTool

Disclaimer : The author takes no responsibility for actions taken against a game account following the use of this software or the files generated with it. The code is written as an intellectual exercise and not to encourage cheating or breaking the EULA of the game targeted.

WIP

Full rewrite in C# of Reunion's bf4 sdk code, specifically for SWBF 2 (2017).

Requires about 50mins to run when calling GetVtable() in SDKClassInfo, 2 mins if not (on my machine). Should scale with no. of logical cores.

0.3b Added multithreading for class typeinfos to assist with time taken to find vtables for lea gettype classes. More fixes for incorrect class dumps.

0.4a Sorts Structs.h by dependency for import into IDA. Generates Declarations.h for importing Classes.h. Added a bool in Main() to switch c++/ida import output for the headers (ida version replaces Array<> types with type poitners). 

0.5 Now produces 2 folders of files - cpp & ida. Each contains 4 headers for direct inclusion, and the ida folder also contains a subfolder of individual .h for each class; this should ease filling the empy classes for re purposes and reintegrating for new patches. Temporarily disabled finding lea gettype vtables due to unfixed bug in the multithreaded code. 

0.5a Fixed some errors for actual compilation of cpp files :D
