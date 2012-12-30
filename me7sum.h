/* me7sum [ firmware management tool for Bosch ME7.x firmware]
   By 360trev
   
   Inspiration from Andy Whittaker's tools and information
   (see http://www.andywhittaker.com/ECU/BoschMotronicME71.aspx)

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
   AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
   OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.
*/
#ifndef _ME7SUM_H_
#define _ME7SUM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "os_types.h"
#include "inifile_prop.h"

int           GetRomInfo(             FILE *fh, struct section *osconfig);
unsigned long CalcChecksumBlk(        FILE *fh, unsigned long nStartAddr,	unsigned long nEndAddr);
unsigned long ReadChecksumBlks(       FILE *fh, unsigned long nStartBlk);
void          ReadMainChecksum(       FILE *fh,	unsigned long nStartaddr,	unsigned long nEndaddr);

#endif
