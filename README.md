# TypeInfoTool

Disclaimer : The author takes no responsibility for actions taken against a game account following the use of this software or the files generated with it. The code is written as an intellectual exercise and not to encourage cheating or breaking the EULA of the game targeted.

WIP

Basic rewrite of Reunion's code, specifically for SWBF 2 (2017).

Requires about 50mins to run when calling GetVtable() in SDKClassInfo, 2 mins if not (on my machine). Should scale with no. of logical cores.

0.3b Added multithreading for class typeinfos to assist with time taken to find vtables for lea gettype classes. More fixes for incorrect class dumps.

0.4a Sorts Structs.h by dependency for import into IDA. Generates Declarations.h for importing Classes.h. Added a bool in Main() to switch c++/ida import output for the headers (ida version replaces Array<> types with type pointers). 
