# TypeInfoTool

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Disclaimer : The author takes no responsibility for actions taken against a game account following the use of this software or the files generated with it. The code is written as an intellectual exercise and not to encourage cheating or breaking the EULA of the game targetted.

WIP

Basic rewrite of Reunion's code, specifically for SWBF 2 (2017).

Does not currently sort classes by dependency, does not produce declarations.h

Requires about 40mins to run when calling GetVtable() in SDKClassInfo, 30secs if not (on my machine). Should scale with no. of logical cores.

0.3b Added multithreading for class typeinfos to assist with time taken to find vtables for lea gettype classes. More fixes for incorrect class dumps
