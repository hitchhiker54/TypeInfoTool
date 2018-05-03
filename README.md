# TypeInfoTool

Basic rewrite of Reunion's code, specifically for SWBF 2 (2017).

Does not currently sort classes by dependency, does not produce declarations.h

Requires about 1 hour to run when calling GetVtable() in SDKClassInfo, 30secs if not.
