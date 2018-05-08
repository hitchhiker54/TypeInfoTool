# TypeInfoTool

WIP

Basic rewrite of Reunion's code, specifically for SWBF 2 (2017).

Does not currently sort classes by dependency, does not produce declarations.h

Requires about 40mins to run when calling GetVtable() in SDKClassInfo, 30secs if not (on my machine). Should scale with no. of logical cores.

0.3b	Added multithreading for class typeinfos to assist with time taken to find vtables for lea gettype classes.
		More fixes for incorrect class dumps
