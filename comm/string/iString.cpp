#include <stdio.h>

#include "iString.h"
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include<algorithm>
#include <stdlib.h> 
#include <sstream>
#include <sstream>
#include "iMd5.h"

using namespace std;

int Comm::StrFind(const char* pcSrc, char cFind, int nStart, bool bCaseSensitive)
{
	if ((pcSrc == NULL) || (nStart < 0))
	{
		return -1;
	}

	for (int i = nStart; '\0' != pcSrc[i]; ++i)
	{
		if (bCaseSensitive)
		{
			if (pcSrc[i] == cFind)
			{
				return i;
			}
		}
		else 
		{	
			if (toupper(pcSrc[i]) == toupper(cFind))
			{
				return i;
			}
		}
	}
	
	return -1;
}

int Comm::StrFind(const char* pcSrc, const char* pcFind, int nStart, bool bCaseSensitive)
{
	if ((pcSrc == NULL) || (pcFind == NULL) || (nStart < 0))
	{
		return -1;
	}

	int nFindLen = strlen(pcFind);
	int nEnd = strlen(pcSrc) - nFindLen;
	if (nFindLen <= 0)
	{
		return -1;
	}
	
	for (int i = nStart; i <= nEnd; ++i)	
	{
		if (bCaseSensitive)
		{
			if (strncmp(pcSrc + i, pcFind, nFindLen) == 0)
			{
				return i;
			}
		}
		else
		{
			if (strncasecmp(pcSrc + i, pcFind, nFindLen) == 0)
			{			
				return i;
			}
		}
	}	
	
	return -1;
}

int Comm::StrFindFirstOf(const char* pcSrc, const char* pcFind, int nStart, bool bCaseSensitive)
{
	if ((pcSrc == NULL) || (pcFind == NULL) || (nStart < 0))
	{
		return -1;
	}

	int nFindLen = strlen(pcFind);
	int nSrcLen = strlen(pcSrc);
	if ((nFindLen <= 0) || (nSrcLen <= 0))
	{
		return -1;
	}

	for (int i = nStart; i < nSrcLen; ++i)
	{
		for (int j = 0; j < nFindLen; ++j)
		{
			if (bCaseSensitive)
			{
				if (pcSrc[i] == pcFind[j])
				{
					return i;
				}
			}
			else 
			{	
				if (toupper(pcSrc[i]) == toupper(pcFind[j]))
				{
					return i;
				}
			}
		}
	}
	
	return -1;

}

void Comm::StrTrim(char* pcSrc, const char* pcTrim)
{
	if ((pcSrc == NULL) || (pcTrim == NULL))
	{
		return;
	}
	
	int nSrcLen = strlen(pcSrc);
	int nTrimLen = strlen(pcTrim);
	if ((nSrcLen == 0) || (nTrimLen == 0))
	{
		return;
	}

	// trim right first 
	int i = 0;
	for (i = nSrcLen - 1; i >= 0; --i)
	{
		int j = 0;
		for (; j < nTrimLen; ++j)
		{
			if (pcSrc[i] == pcTrim[j])
			{
				pcSrc[i] = '\0';
				break;
			}
		}

		if (j == nTrimLen)	// current is not trim char
		{
			break;
		}
	}
	
	nSrcLen = i + 1;	// pcStr[i + 1] is '\0'
		
	// trim left
	for (i = 0; i < nSrcLen; ++i)
	{
		int j = 0;
		for (; j < nTrimLen; ++j)
		{
			if (pcSrc[i] == pcTrim[j])
			{
				break;
			}
		}

		if (j == nTrimLen)	// current is not trim char
		{
			break;
		}
	}

	// no trim char at the left
	if (i == 0)
	{
		return;
	}

	memmove(pcSrc, &(pcSrc[i]), nSrcLen - i + 1);	// move strings and '\0'
}

void Comm::StrTrim(string& sSrc, const string& sTrim)
{
	string::size_type nStartPos = 0;
	string::size_type nEndPos = 0;
	nStartPos = sSrc.find_first_not_of(sTrim);
	nEndPos = sSrc.find_last_not_of(sTrim);
	if (nStartPos == string::npos || nEndPos == string::npos) 	
	{		
		sSrc = "";
		return ;
	}	
	if (nEndPos >= nStartPos)  
	{		
		sSrc = sSrc.substr(nStartPos, nEndPos - nStartPos + 1);
		return ;
	}	
}

void Comm::StrUpper(char* pcSrc)
{
	if (pcSrc != NULL)
	{
		int i=0;
		while ( '\0' != pcSrc[i] )
		{
			if ( ('a' <= pcSrc[i]) && ('z' >= pcSrc[i]) )
			{
				pcSrc[i] = pcSrc[i] - 'a' + 'A';
			}
			++i;
		}
	}
}

void Comm::StrUpper(string& sSrc)
{
	int nLen = sSrc.length();
	for(int i = 0; i < nLen; ++i)	
	{		
		if ( ('a' <= sSrc[i]) && ('z' >= sSrc[i]) )
		{
			sSrc[i] = sSrc[i] - 'a' + 'A';
		}
	}	
}	
	
void Comm::StrLower(char* pcSrc)
{
	if (pcSrc != NULL)
	{
		int i=0;
		while ( '\0' != pcSrc[i] )
		{
			if ( ('A' <= pcSrc[i]) && ('Z' >= pcSrc[i]) )
			{
				pcSrc[i] = pcSrc[i] - 'A' + 'a';
			}
			++i;
		}
	}
}

void Comm::StrLower(string& sSrc)
{
	int nLen = sSrc.length();
	for(int i = 0; i < nLen; ++i)	
	{		
		if ( ('A' <= sSrc[i]) && ('Z' >= sSrc[i]) )
		{
			sSrc[i] = sSrc[i] - 'A' + 'a';
		}
	}	
}

void Comm::StrnCpy(char* pcDst, const char* pcSrc, int nDstLen)
{
	if ((pcDst == NULL) || (pcSrc == NULL) || (nDstLen <= 0))
	{
		return;
	}

	--nDstLen;
	for (int i = 0; (i < nDstLen) && (*pcSrc != '\0'); ++i)
	{
		*pcDst = *pcSrc;
		pcDst++;
		pcSrc++;
	}
	*pcDst = '\0';
}

char *Comm::StrnCat(char* pcDst, const char* pcSrc, int nDstLen)
{
	if ((pcDst == NULL) || (pcSrc == NULL) || (nDstLen <= 0))
	{
		return pcDst;
	}

	register int nLen = strlen(pcDst);
	StrnCpy(pcDst+nLen, pcSrc, nDstLen-nLen);
	return pcDst;
}

int Comm::StrCmp(const char* pcStr1, const char* pcStr2, bool bCaseSensitive)
{
	if (pcStr1 == NULL)
	{	
		if (pcStr2 == NULL)
		{
			return 0;
		}
		return -1;	
	}
	if (pcStr2 == NULL)
	{
		return 1;
	}
	
	if (bCaseSensitive)
	{
		return strcmp(pcStr1, pcStr2);
	}
	else
	{
		return strcasecmp(pcStr1, pcStr2);
	}
}
	
int Comm::StrnCmp(const char* pcStr1, const char* pcStr2, int nLen, bool bCaseSensitive)
{
	if (nLen <= 0)
	{
		return 0;
	}
	if (pcStr1 == NULL)
	{	
		if (pcStr2 == NULL)
		{
			return 0;
		}
		return -1;	
	}
	if (pcStr2 == NULL)
	{
		return 1;
	}
	
	if (bCaseSensitive)
	{
		return strncmp(pcStr1, pcStr2, nLen);
	}
	else
	{
		return strncasecmp(pcStr1, pcStr2, nLen);
	}
}

bool Comm::StrEqual(const char* pcStr1, const char* pcStr2, bool bCaseSensitive)
{
	return StrCmp(pcStr1, pcStr2, bCaseSensitive) == 0;
}
	
void Comm::StrSplitList(const char* pcStr, const char* pcDelimiter, bool bFullCheck, vector<string>& vecResult)
{
	if ((pcStr == NULL) || (pcDelimiter == NULL))
	{
		return;
	}

	int nNewPos ;
	int nPos;  
	if (bFullCheck)
	{
		nNewPos = StrFind(pcStr, pcDelimiter);
	}
	else 
	{
		nNewPos = StrFindFirstOf(pcStr, pcDelimiter);
	}

	if (nNewPos < 0)
	{
		vecResult.push_back(pcStr);
		return;
	} 
	
	if (nNewPos != 0)
	{
		vecResult.push_back(string(pcStr, nNewPos));
	} 

	if (bFullCheck)
	{
		int nItemLen = strlen(pcDelimiter);

		while ((nPos = StrFind(pcStr, pcDelimiter, nNewPos + nItemLen)) > 0)
		{
			if (nPos != nNewPos + nItemLen) 
			{
				vecResult.push_back(string(&(pcStr[nNewPos + nItemLen]), nPos - nNewPos - nItemLen));
						
			}  
			else
			{
				vecResult.push_back( "" );
			}
			nNewPos = nPos;
		} 
		if ((unsigned int)(nNewPos + nItemLen) < strlen(pcStr))
		{
		  	vecResult.push_back(string(&(pcStr[nNewPos + nItemLen])));
		}
		else if ((unsigned int)(nNewPos + nItemLen) == strlen( pcStr ))
		{
			vecResult.push_back( "" );
		}
	}
	else
	{
		int nItemLen = 1;

		while ((nPos = StrFindFirstOf(pcStr, pcDelimiter, nNewPos + nItemLen)) > 0)
		{
			if (nPos != nNewPos + nItemLen)
			{
				vecResult.push_back(string(&(pcStr[nNewPos + nItemLen]), nPos - nNewPos - nItemLen));
			}
			else
			{
				vecResult.push_back( "" );
			}
			nNewPos = nPos;
		}
		if ((unsigned int)(nNewPos + nItemLen) < strlen(pcStr)) 
		{
		   	vecResult.push_back(string(&(pcStr[nNewPos + nItemLen])));
		}
		else if ((unsigned int)(nNewPos + nItemLen) == strlen( pcStr ))
		{
			vecResult.push_back( "" );
		}
	}
}
	
const char* Comm::StrQuotedSplit(char* pcResult, int nResultLen, const char* pcSrc, int nIndex, 
		const char** ppcNext, char cDelimiter)
{
	if ((pcResult == NULL) || (nResultLen <= 0) || (pcSrc == NULL) || (nIndex < 0))
	{
		return pcResult;
	}

	int nQuoted = 0;
   	int nSize = 0;
	int nSpec = 0;
	const char* pcNext = pcSrc;
	const char* pcResultTmp = pcResult;
	const char* pcRet = NULL ;

	for (; nIndex >= 0; nIndex--) 
	{
		for (; isspace(*pcNext); pcNext++); // skip the leading spaces of each sub string
		
		if ((nQuoted = *pcNext == '\"'))
		{
			pcNext++;
		}
		
		for (; *pcNext != '\0' && (nQuoted || (cDelimiter && *pcNext != cDelimiter || !cDelimiter && *pcNext != ' ' && 
						*pcNext != '\t' && *pcNext != '\r' && *pcNext != '\n')); pcNext++)
	   	{
			if (nIndex == 0)
		   	{
				pcRet = pcResultTmp; /* return value here, point to the buffer */
				if (*pcNext == '\\' && (*(pcNext + 1) == '\"' || *(pcNext + 1) == '\\'))
				{
					nSpec = !nSpec;
				}
				else
				{
					nSpec = 0 ;
				}
				
				if (nSpec == 0 && nSize < nResultLen - 1 /* the result buffer must be large enough */
						&& (*pcNext != '\"' || pcNext > pcSrc && *(pcNext - 1) == '\\'))
				{
					*pcResult++ = *pcNext, nSize ++ ; /* copy the sub string byte by byte */
				}
			}
			
			if (*pcNext == '\"' && pcNext > pcSrc && *(pcNext - 1) != '\\')
			{
				nQuoted = (nQuoted == 0 ? 1 : 0); /* whether in a quoted sub string ? */
			}
		}
		
		if (*pcNext != '\0' && *pcNext == cDelimiter)
		{
			pcNext++;
		}
	} /* for */
	
	for (; isspace(*pcNext); pcNext++) ;

	*pcResult = '\0';
	if (ppcNext != NULL)
	{
		*ppcNext = pcNext && *pcNext ? pcNext : NULL;
	}
	return pcRet;
}

const char* Comm::StrEnclose(const char* pcStr, char cLeftEnclose, char cRightEnclose, int* pnLen)
{
	if ((pcStr == NULL) || (pnLen == NULL))
	{
		return NULL;
	}
	
	*pnLen = 0;
	int nPos = StrFind(pcStr, cLeftEnclose);
	if (nPos < 0)
	{
		return NULL;
	}
	
	const char* pcStart = pcStr + nPos + 1;
	nPos = StrFind(pcStart, cRightEnclose);
	if (nPos < 0)
	{
		return NULL;
	}
	
	*pnLen = nPos;
	return pcStart;
}
	
string Comm::StrEnclose(const char* pcStr, char cLeftEnclose, char cRightEnclose)
{
	int nLen = 0;
	const char* pcResult = StrEnclose(pcStr, cLeftEnclose, cRightEnclose, &nLen);
	if ((pcResult == NULL) || (nLen <= 0))
	{
		return "";
	}
		
	return string(pcResult, nLen);
}

int Comm::StrIsInteger(const char *sString)
{
	int n;

	for(n=0; sString[n]!=0; ++n)
	{
		if(isdigit(sString[n]) == 0 && (sString[n] != '-' || n != 0))
			return(1);
	}
	return(0);
}

string Comm::StrFormat(const char* pcFmt, ...)
{
   	if (pcFmt == NULL)
	{
	 	return "";
	}
	string s;
   	va_list va;

	va_start(va, pcFmt);
	size_t nLen = vsnprintf(NULL, 0, pcFmt, va);
	if (nLen > 0)
   	{
        va_list va2;
        va_start(va2, pcFmt);

   		s.resize(nLen);
		char* sTmp = (char*)s.c_str();
		vsnprintf(sTmp, nLen + 1, pcFmt, va2);

        va_end(va2);
	}
	va_end(va);

	return s;	
}


void Comm::StrFormat(string& sStr, const char* pcFmt, ...)
{
	sStr = "";
   	if (pcFmt == NULL)
	{
	 	return;
	}
   	va_list va;
	va_start(va, pcFmt);
	size_t nLen = vsnprintf(NULL, 0, pcFmt, va);
	if (nLen > 0)
   	{
        va_list va2;
        va_start(va2, pcFmt);

   		sStr.resize(nLen);
		char* sTmp = (char*)sStr.c_str();
		vsnprintf(sTmp, nLen + 1, pcFmt, va2);

        va_end(va2);
	}
	va_end(va);
}

char* Comm::MemSearch(char *pDst, char *pPat, int nDstLen, int nPatLen)
{
    if(!pDst || !pPat || nPatLen>nDstLen) return NULL;
  
    register int i, j;   
    int *pPatArray = new int[nPatLen];  
    if(!pPatArray) return NULL;
	    pPatArray[0] = -1;
    for(j=1; j < nPatLen; j++)
    {
        i = pPatArray[j-1];
        while(*(pPat+j) != *(pPat+i+1) && i>=0) i = pPatArray[i];
        if(*(pPat+j) == *(pPat+i+1)) pPatArray[j] = i+1;
        else pPatArray[j] = -1;
    }

    i = 0; j=0; 
    while(i<nPatLen && j<nDstLen)
    {
        if(pPat[i] == pDst[j])
        {       
            i++;    
            j++;    
        }       
        else if(i==0) j++;
        else i = pPatArray[i-1] + 1;
    }
    delete [] pPatArray;

    if(i<nPatLen) return NULL;
    else return (pDst+j-nPatLen);
}


const char * Comm::ParseString ( register char *asResult, int aiResultSize,
	const char *asSource, int aiIndex, const char **appcNext , char acDelimitor )
{
	int liQuoted, liSize = 0, liSpec = 0 ;
	const char *lpcNext = asSource, *lpcResult = asResult, *lpcRet = NULL ;

	if ( asSource != NULL )
	{
		for ( ; aiIndex >= 0; aiIndex -- )
		{
			for ( ; IsSpace ( *lpcNext ); lpcNext ++ ) ; // skip the leading spaces of each sub string
				if ( (liQuoted = *lpcNext == '\"') )
					lpcNext ++ ;
			for ( ; *lpcNext != '\0' && ( liQuoted || ( acDelimitor && *lpcNext != acDelimitor
			|| !acDelimitor && *lpcNext != ' ' && *lpcNext != '\t' && *lpcNext != '\r' && *lpcNext != '\n' ) ); lpcNext ++ )
			{
				if ( aiIndex == 0 )
				{
					lpcRet = lpcResult ; /* return value here, point to the buffer */
					if ( *lpcNext == '\\' && (*(lpcNext + 1) == '\"' || *(lpcNext + 1) == '\\') )
						liSpec = ! liSpec ;
					else
						liSpec = 0 ;
					if ( liSpec == 0 && liSize < aiResultSize - 1 /* the result buffer must be large enough */
              			&& (*lpcNext != '\"' || lpcNext > asSource && *(lpcNext - 1) == '\\') )
						*asResult ++ = *lpcNext, liSize ++ ; /* copy the sub string byte by byte */
				}
				if ( *lpcNext == '\"' && lpcNext > asSource && *(lpcNext - 1) != '\\' )
					liQuoted = ( liQuoted == 0 ? 1 : 0 ); /* whether in a quoted sub string ? */
			}
			if ( *lpcNext != '\0' && *lpcNext == acDelimitor )
				lpcNext ++ ;
		} /* for */
		for ( ; IsSpace (*lpcNext); lpcNext ++ ) ;
	}
	*asResult = '\0' ;
	if ( appcNext != NULL )
		*appcNext = lpcNext && *lpcNext ? lpcNext : NULL ;
	return lpcRet ;
}

int Comm::IsSpace ( register int c )
{
  return ( c != '\0' && (c & 0x80) == 0 && isspace ( c ) ) ;
}

int Comm::IsAlnum ( register int c )
{
  return ( c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ) ;
}

int Comm::IsDigit ( register int c )
{
  return ( c >= '0' && c <= '9' ) ;
}

int Comm::IsAlpha ( register int c )
{
  return ( c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ) ;
}

#define min(a,b) ((a)>(b) ? (b):(a))

int Comm::StringToBitmap(const char *asString,char *pBitsBuff,size_t nBuffSize)
{
     memset(pBitsBuff,0x0,nBuffSize);
     size_t nStringLen = strlen(asString) ; //有多少个bit
     size_t nBitCount = min(nStringLen,nBuffSize * 8);
     for(size_t i = 0 ; i < nBitCount ; i++ ) 
     {
            if('1' == asString[i])
            {       
                    pBitsBuff[ i / 8 ] |= (1 << (i % 8));  
            }       
     } 
     return nBitCount;
}
/// 0xFF => "11111111"
string Comm::BitmapToString(char *pBitsBuff,size_t nBitCount)
{

    char szResult[ nBitCount + 1];
    memset(szResult,'0',sizeof(szResult)-1);
    szResult[ sizeof(szResult) -1 ] = '\0'; 
    for(size_t i=0;i<nBitCount;i++)
    {       
           unsigned char flag = ((unsigned char)1 << (i % 8 )); 
           szResult[ i ] = ( (pBitsBuff[i/8] & flag) ? '1' : '0' );
         
    }       
    return szResult;
}

void Comm::StrReplaceAll( string & haystack, string needle, string s )
{
	string::size_type pos = 0;
	while ( ( pos = haystack.find ( needle, pos ) ) != string::npos )
	{
		haystack.erase ( pos, needle.length() );
		haystack.insert ( pos, s );
		pos += s.length();
	}
}

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* same, but slower, works on systems that might have 8 byte ub4's */
#define mix2(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<< 8); \
  c -= a; c -= b; c ^= ((b&0xffffffff)>>13); \
  a -= b; a -= c; a ^= ((c&0xffffffff)>>12); \
  b -= c; b -= a; b = (b ^ (a<<16)) & 0xffffffff; \
  c -= a; c -= b; c = (c ^ (b>> 5)) & 0xffffffff; \
  a -= b; a -= c; a = (a ^ (c>> 3)) & 0xffffffff; \
  b -= c; b -= a; b = (b ^ (a<<10)) & 0xffffffff; \
  c -= a; c -= b; c = (c ^ (b>>15)) & 0xffffffff; \
}

unsigned long int Comm::StringHash(
	register char *k,            /* the key */
	register unsigned long  int length,   /* the length of the key */
	register unsigned long  int initval   /* the previous hash, or an arbitrary value */
)
{
   register ub4 a,b,c,len;

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;           /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
      b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
      c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((ub4)k[10]<<24);
   case 10: c+=((ub4)k[9]<<16);
   case 9 : c+=((ub4)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((ub4)k[7]<<24);
   case 7 : b+=((ub4)k[6]<<16);
   case 6 : b+=((ub4)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((ub4)k[3]<<24);
   case 3 : a+=((ub4)k[2]<<16);
   case 2 : a+=((ub4)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

string Comm::Left(const string & sStr,int nCount)
{
	return string(sStr.substr(0,nCount));
}
string Comm::Right(const string &sStr, int nCount)
{
	return sStr.substr(sStr.length()-nCount,nCount);
}

string Comm::AllTrim(const string &sStr,const string & sToTrim)
{
	int lBegin=0,lEnd=sStr.length()-1;
	for(;strchr(sToTrim.c_str(),sStr[lBegin]) && lBegin < lEnd;lBegin++)
		;
	for(;strchr(sToTrim.c_str(),sStr[lEnd]) && lBegin <= lEnd;lEnd--)
		;
	return sStr.substr(lBegin,lEnd-lBegin+1);
}

string Comm::LeftTrim(const string &sStr,const string & sToTrim)
{
	int lBegin=0,lEnd=sStr.length()-1;
	for(;strchr(sToTrim.c_str(),sStr[lBegin]) && lBegin <= lEnd;lBegin++)
		;
	return sStr.substr(lBegin,lEnd-lBegin+1);
}

string Comm::RightTrim(const string &sStr,const string & sToTrim)
{
	int lBegin=0,lEnd=sStr.length()-1;
	for(;strchr(sToTrim.c_str(),sStr[lEnd]) && lBegin <= lEnd;lEnd--)
		;
	return sStr.substr(lBegin,lEnd-lBegin+1);
}

int Comm::StrToInt(const string &sStr)
{
	return atoi(sStr.c_str());	
}

unsigned int Comm::StrToUInt(const string &sStr)
{
	return strtoul(sStr.c_str(), NULL, 10);
}

long long int Comm::StrToLLInt(const string &sStr)
{
	return atoll(sStr.c_str());
}

unsigned int Comm::BufferToUInt(const char *psz)
{
	if ( (NULL == psz) || ('\0' == *psz) )
	{
		return 0;
	}

	return strtoul(psz, NULL, 10);
}

string Comm::Mid(const string & sStr,long lBegin)
{
	if(lBegin<0 || (unsigned)lBegin>=sStr.size()) return "";
	return sStr.substr(lBegin,sStr.size()-lBegin);

}

string Comm::Mid(const string & sStr,long lBegin,long lCount)
{
	if(lCount<0 || lBegin<0 || (unsigned)lBegin>=sStr.size()) return "";
	return sStr.substr(lBegin,lCount);
}

string Comm::Padl(const string & sStr,unsigned long lCount,char ch)
{
	if(sStr.size()>=lCount)
		return sStr;
	else		
		return  string(lCount-sStr.size(),ch) + sStr;
}

string Comm::IntToStr(const int i)
{
	char szStr[16];
	sprintf(szStr,"%d",i);
	return string(szStr);
}

string Comm::UIntToStr(const unsigned int i)
{
	char szStr[16];
	sprintf(szStr,"%u",i);
	return string(szStr);
}

string Comm::LLIntToStr(const long long int i)
{
	char szStr[32];
	sprintf(szStr, "%lld", i);
	return string(szStr);
}

string Comm::ULLIntToStr(const unsigned long long int i)
{
	char szStr[32];
	sprintf(szStr, "%llu", i);
	return string(szStr);
}

int Comm::SeparateText(vector<string> &slStringList,const string &sStr,const char cSeparator)
{
	int nLength = sStr.length();
	int i =0, j = 0;
	int nCount=0;
	slStringList.clear();
	while((j=sStr.find(cSeparator,i)) != -1)
	{
			if(i!=j)
			{
				slStringList.push_back(sStr.substr(i,j-i));
				nCount++;
			}
			i=j+1;
	}
	if(i<nLength)
	{
				slStringList.push_back(sStr.substr(i,nLength-i));
				nCount++;
	}
	return nCount;
}

//根据分隔符，取字符串的第N个子串（0开始）
string Comm::GetSeperatedTextByIndex(const string &sStr,const int nIndex,const string & sSeparatorList)
{
	int nLength = sStr.length();
	int nCount=0;
	char * pBegin=(char*)sStr.c_str();
	char * pEnd=NULL;
	while((pEnd=strpbrk(pBegin,sSeparatorList.c_str()))!=NULL)
	{
		//if(pBegin!=pEnd)
		{
			if(nCount==nIndex)return sStr.substr(pBegin-sStr.c_str(),pEnd-pBegin);
			nCount++;
		}
		pBegin=pEnd+1;
	}
	if((pBegin-sStr.c_str())<nLength)
	{
		if(nCount==nIndex)return sStr.substr(pBegin-sStr.c_str(),nLength-(pBegin-sStr.c_str()));
		nCount++;
	}
	return "";
}


int Comm::BCBToStr(const char * szBCBStr,char * szStr)
{
	int nResultLen=0;

    long i;
    char c1, c2;

    //====== 1. 循环处理每一个字符 ======
    for (i = 0; '\0' != szBCBStr[i]; i++)
    {
        c1 = szBCBStr[i];
        //====== 2. 处理高位 ======
        c2 = (c1 >> 4) & 0x0F;
        if (c2 == 0x00)
            break;
        if (c2 >= 0x01 && c2 <= 0x09)
            c2 = c2 + 0x30;
        else if (c2 == 0x0A)
            c2 = '0';
        else
			return -1;
        szStr[nResultLen] = c2;
		nResultLen++;

        //====== 3. 处理低位 ======
        c2 = c1 & 0x0F;
        if (c2 == 0x00)
            break;
        if (c2 >= 0x01 && c2 <= 0x09)
            c2 = c2 + 0x30;
        else if (c2 == 0x0A)
            c2 = '0';
        else
        	return -1;
		szStr[nResultLen] = c2;
		nResultLen++;
    }
	return nResultLen;
}


int Comm::StrToBCB(const char * szNumStr,char * szStr)
{
    //int nLen;
	int nResultLen=0;

    long i;
    char c1, c2 = 0;

    //====== 1. 循环处理每一个字符 ======
    for (i = 0; '\0' != szNumStr[i]; i++)
    {
        c1 = *(szNumStr + i);
        if (c1 < '0' || c1 > '9')
			return -1;

        //====== 2. 处理前一个字符 ======
        if (i % 2 == 0)
        {
            if (c1 >= '1' && c1 <= '9')
                c2 = (c1 - 0x30) << 4;
            else
            {
                assert(c1 == '0');
                c2 = 0xA0;
            }
        }
        else
        {
            if (c1 >= '1' && c1 <= '9')
                c2 = (c1 - 0x30) | c2;
            else
            {
                assert(c1 == '0');
                c2 = 0x0A | c2;
            }

            szStr[nResultLen] = c2;
			nResultLen ++;
        }
    }

    if (i % 2 == 1)
	{
		szStr[nResultLen] = c2;
		nResultLen ++;
	}
	return nResultLen;
}

bool Comm::FilterStr(const string &sStr,const string &sFilter)
{
	return FilterStr(sStr.c_str(),sFilter.c_str());
}


bool Comm::FilterStr(const char  * const str,const char * const filter)
{
	//nps,npf:分别为字符串和filter的位置指针
	int nps=0,npf=0;
	//nlps,nlpf:分别为字符串和filter上一个遇到*号的位置(以下简称*号点)
	//理解算法的关键在于对"*号点位置的记录和回溯"

	int nlps=-1,nlpf=-1;

	int nlenstr = strlen(str);
	int nlenfilter = strlen(filter); 

	if(nlenstr == 0 && nlenfilter ==0)
	{
		return false;//空str和空filter不匹配
	}

	while(true)
	{
		switch (filter[npf])
		{
		case '*':
			if(npf == (nlenfilter-1))
			{
				//printf("filter最后一个为*,匹配结束\n");
				return true;
			}
			//保存*号点,以便后面匹配不成功回退
			nlpf=npf;
			npf++;

			nlps=nps;
			//这里字符串的位置nps并不++,以使*号可以表示0个字符.
			break;
		case '?':
			nps++;
			npf++;
			break;
		default:
			if(filter[npf] == str[nps])
			{
				nps++;
				npf++;
			}
			else
			{
				if(nlps != -1)
				{
					//如果上一个*号点存在,回退到上一个*号点后
					nps=++nlps;
					npf=nlpf;
				}
				else
				{
					//printf("遭遇无法匹配的终结符,没有上一个*号点可以回退,无法匹配\n");
					return false;
				}
			}
		}
		if(nps == nlenstr )
		{
			if(npf == nlenfilter)
			{
				//printf("字符串结束，filter也刚好结束，匹配成功\n");
				return true;
			}
			else if(npf == nlenfilter -1 && filter[npf] == '*')
			{
				//printf("字符串结束,filter还剩下一个*号(*号代表空字符),匹配成功\n");
				return true;
			}
			else
			{
				//printf("字符串结束,filter中还有未匹配字符,匹配失败\n");
				return false;
			}
		}
	}

}

bool Comm::IsUpperAlphabetString(const string & sStr)
{
	const char  * const psz=sStr.c_str();
	for(int i=strlen(psz)-1;i>=0;i--)
	{
		if(isupper(*(psz+i))==0)
			return false;
	}
	return true;
}

bool Comm::IsNumber(const string & sStr)
{
	if(sStr.empty()) return false; //add by sunny061123
	return IsNumber(sStr.c_str());
//	const char  * const psz=sStr.c_str();
//	char ch;
//	for(int i=strlen(psz)-1;i>=0;i--)
//	{
//		ch=*(psz+i);
//		if(isdigit(ch)==0)
//		{
//			if(i==0&& (ch=='-' || ch=='+'))return true;//首位可以是正负号
//			return false;
//		}
//	}
//	return true;
}
bool Comm::IsNumber(const char * psz)
{
	if(psz[0]=='\0')return false;
	char ch;
	for(int i=strlen(psz)-1;i>=0;i--)
	{
		ch=*(psz+i);
		if(isdigit(ch)==0||ch<0)
		{
			if(i==0&& (ch=='-' || ch=='+'))return true;//首位可以是正负号
			return false;
		}
	}
	return true;
}
bool Comm::IsFloat(const string & sStr)
{
	if(sStr.empty()) return false; //add by sunny061123
	return IsFloat(sStr.c_str());
}
bool Comm::IsFloat(const char * psz)
{
	if(psz[0]=='\0')return false;
	char ch;
	int nDecimalPoint = 0;
	for(int i=strlen(psz)-1;i>=0;i--)
	{
		ch=*(psz+i);
		if(isdigit(ch)==0||ch<0)
		{
			if(i==0&& (ch=='-' || ch=='+'))return true;//首位可以是正负号
			if (i>0 && isdigit(psz[i-1]) != 0 && ch=='.' && nDecimalPoint == 0)
			{
				//不允许 ".1"，"-.1" 这种表述，虽然这种表述能在js解析
				nDecimalPoint++;
				continue;
			}
			return false;
		}
	}
	return true;
}

string Comm::Replace(const string& sStr,const string sToFind,const string &sReplaceWith)
{
	if(sToFind.empty())return sStr;
	string sRet;
	size_t nEndPos,nBeginPos;
	nBeginPos=nEndPos=0;
	while((nEndPos = sStr.find(sToFind, nBeginPos)) != string::npos)
	{
		sRet+=Mid(sStr,nBeginPos,nEndPos-nBeginPos);
		sRet+=sReplaceWith;
		nBeginPos = nEndPos + sToFind.size();
	}
	nEndPos=sStr.length();
	sRet+=Mid(sStr,nBeginPos,nEndPos-nBeginPos);
	return sRet;
}

bool Comm::IsAsciiStr(const string & sStr)
{
	const char  * const psz=sStr.c_str();
	for(int i=strlen(psz)-1;i>=0;i--)
	{
		if(isascii(*(psz+i))==0)
			return false;
	}
	return true;
}

string Comm::ToLowerCase(const string & sSrc)
{
	string sDest=sSrc;
	std::transform( sDest.begin(), sDest.end(), sDest.begin(), ::tolower);
	return sDest;
}

string Comm::ToUpperCase(const string & sSrc)
{
	string sDest=sSrc;
	std::transform( sDest.begin(), sDest.end(), sDest.begin(), ::toupper);
	return sDest;
}


string Comm::NumericCharacterEntities(string sStr, const string sSearchWord, const int nBase, char cEndChar)
{
	char a;
	size_t nPos=sStr.find(sSearchWord);
	char *EndStr;
	string sResult;
	int i;
	char szBuf[2048];
	snprintf(szBuf,sizeof(szBuf),"%s",sStr.c_str());
	string sTemp=szBuf;

	while(nPos != string::npos)
	{
		sResult += sTemp.substr(0,nPos);
		sTemp = sTemp.substr(nPos + sSearchWord.length());
		
		i = strtol(sTemp.c_str(), &EndStr, nBase);
		a = i;
		if ( (cEndChar!='\0') && (EndStr[0] != cEndChar) || (i == 0))//不是正确的格式，不转换
		{
			sResult += sSearchWord;
		}
		else
		{
			sResult += a;
			if (EndStr[0] == '\0')
			{
				sTemp = "";
			}
			else if ((EndStr[0] == cEndChar) || (EndStr[0] == ';'))	//暂时先这样处理了，如果出现默认结束符号不是';'，再做改进
			{
				sTemp = &EndStr[1];
			}
			else sTemp = &EndStr[0];
		}
		
		nPos = sTemp.find(sSearchWord);

	}
	sResult += sTemp;
	return sResult;
}

bool Comm::stringsAreEqual(const std::string& s1,const std::string& s2)
{
    if (s2.size() != s1.size()) return false;
    else    
    {
        if(strcasecmp((char*)s1.c_str(), (char*)s2.c_str()) == 0) return true;
        else return false;
    }
}

// case-insensitive string comparison
bool Comm::stringsAreEqual(const std::string& s1,const std::string& s2,size_t n)
{
    if(strncasecmp((char*)s1.c_str(), (char*)s2.c_str(), n) == 0) return true;
    else return false;
}

std::string Comm::extractBetween(const std::string& data,const std::string& separator1,const std::string& separator2)
{
    std::string result;
    size_t start, limit;
    start = data.find(separator1, 0);
    if(start != std::string::npos) {
        start += separator1.length();
        limit = data.find(separator2, start); 
        if(limit != std::string::npos)
            result = data.substr(start, limit - start); 
    }
    return result; 
}


char * Comm::extractBetween(char *pData,const char* separator1,const char* separator2)
{
	return extractBetween( pData, (char*)separator1, (char*)separator2 );
}
char * Comm::extractBetween(char *pData,char* separator1,char* separator2)
{
    if(!pData || !separator1 || !separator2) return NULL;
    char *p1, *p2, *pRst=NULL;
    p1 = strstr(pData, separator1);
    if(p1)
    {
        p1+=strlen(separator1);
        p2 = strstr(p1, separator2);
        if(p2)
        {
			pRst = new char[p2-p1+1];
            strncpy(pRst, p1, p2-p1);
            pRst[p2-p1] = 0;
        }
    }
    return pRst;
}

string Comm::GetNext(const string & sStr,size_t & nStartPos,const TECharSet emCharSet)
{
	unsigned char * pcTmpByte = (unsigned char*)sStr.c_str()+nStartPos;
	unsigned char cPattern = 0xC0;
	size_t nBytes=0;
	switch(emCharSet)
	{
		case csGBK:
			if ((*pcTmpByte & 0x80)&&(*pcTmpByte != 0x80)&&(*pcTmpByte != 0xFF))
			{
				nBytes= 2;
			}
			else nBytes= 1;
			break;
		case csGB18030:
			if ((*pcTmpByte & 0x80)&&(*pcTmpByte != 0x80)&&(*pcTmpByte != 0xFF))
			{
				if (*(pcTmpByte+1)>=0x30 && *(pcTmpByte+1)<=0x39)
				{
					nBytes= 4;	
				}
				else
				{
					nBytes= 2;
				}
			}
			else nBytes= 1;
			break;
		case csUTF8:
			nBytes = 2;
			if ((*pcTmpByte & 0x80)&&(*pcTmpByte != 0x80)&&(*pcTmpByte != 0xFF))
			{
				if ((*pcTmpByte & 0xC0) != 0xC0)
				{
					nBytes= 1;
				}
				else
				{
					while (((cPattern>>1|0x80)&(*pcTmpByte))!=cPattern)
					{
						nBytes++;
						cPattern = (cPattern>>1)|0x80;
						if(nBytes>6)
						{
							break;
						}

					}
					if (cPattern >= 0xFE)
					{
						nBytes= 1;
					}
				}
			}
			else 
			{
				nBytes= 1;
			}
			break;
		default: 
			nBytes=1;
	}
	char szBuf[8]={0};
	memcpy(szBuf,pcTmpByte,nBytes);
	nStartPos+=nBytes;
	return string(szBuf);
}

string Comm::StrToHex( const char * sSrc, size_t len )
{
	stringstream ss;
	char hex[3] = {0};
	for(size_t i = 0; i < len; ++i) {
		snprintf(hex, sizeof(hex), "%02x", (unsigned char)(sSrc[i]));
		ss << hex;
	}
	return ss.str();
}

string Comm::StrToHex(const string & sStr)
{
	return StrToHex( sStr.c_str(), sStr.size() );
}

unsigned char Comm::HexToByte(char c) {
    if (c >= '0' && c <= '9') {
        return (unsigned char)(c - '0');
    } else if (c >= 'a' && c <= 'f') {
        return (unsigned char)(10 + c - 'a');
    } else if (c >= 'A' && c <= 'F') {
        return (unsigned char)(10 + c - 'A');
    } else { //出现异常字符
        return 0xff;
    }
}

std::string Comm::HexToStr(const std::string &sHex) {
    unsigned char high, low;
    string result;
    const char *s = sHex.c_str();
    while (*s) {
        //高4位
        high = HexToByte(*s++);
        if (high == 0xff || *s == '\0') {
            return result;
        }

        //低4位
        low = HexToByte(*s++);
        if (low == 0xff) {
            return result;
        }

        result.push_back( (char)((high << 4) | low) );
    }
    return result;
}

std::string Comm::LogPrefix(const char* pcFile,const int iLen ,const char *pcFunc)
{
	std::stringstream ss;
	ss<<STR_GET_PRINT(pcFile)<<":"<<iLen<<" "<<STR_GET_PRINT(pcFunc);
	return ss.str();
}
	
const std::string Comm::CommStrShortWord(const std::string& sData, float fRatio)
{
	float fRealRatio = fRatio;
	if( fRealRatio <= 0 )
	{
		fRealRatio = 0.1;
	}
	if( fRealRatio > 0.7 )
	{
		fRealRatio = 0.7;
	}
	unsigned int iRealSize = (unsigned int)(sData.size()*fRealRatio);
	if( iRealSize > 10 )
	{
		iRealSize = 10;
	}else if( iRealSize == 0 )
	{
		return "-";
	}
	std::string sBuf = sData.substr(0,iRealSize );
	for(size_t i = 0; i < sBuf.size(); i++)
	{
		if( !isprint(sBuf[i]) || '\n'==sBuf[i] || '\r' == sBuf[i])
		{
			//sBuf[i]='-';
		}
	}
	return sBuf;
}

const std::string Comm::CommStrFuseWord(const string& sData)
{
	std::string sBuf;
	//不能输出太长，避免错误的char*搞进来搞死
	for(size_t i = 0; i< sData.size() && i < 16; i++)
	{
		sBuf.append(1,sData[i]);
		if( !isprint(sBuf[i]) || '\n'==sBuf[i] || '\r' == sBuf[i])
		{
			//sBuf[i]='-';
		}
		if( sData.size() < 9 )
		{
			if( i >=3 && i < 7 )
			{
				sBuf[i]='*';
			}
		}else if( i >=3 && ( i < (sData.size() - 3) && i < 14 ))
		{
			sBuf[i]='*';
		}
	}
	return sBuf;
}

void Comm::DeviceId2Uuid(const unsigned char *cDeviceID, string &sUuid)
{
	char cUuid[33];
	for(int i = 0; i< 16;i++)
	{
		snprintf(cUuid+i*2,3,"%02x",(unsigned char)cDeviceID[i]);
	}
	cUuid[32]='\0';

	Comm::MD5::hex_digest( (char*)cUuid, strlen( cUuid ), &sUuid );
}

void * Comm::MemDup( const void * ptr, size_t len )
{
	char * ret = (char*)malloc( len + 1 );

	memcpy( ret, ptr, len );
	ret[ len ] = '\0';

	return ret;
}

//gzrd_Lib_CPP_Version_ID--start
#ifndef GZRD_SVN_ATTR
#define GZRD_SVN_ATTR "0"
static char gzrd_Lib_CPP_Version_ID[] __attribute__((used))="$HeadURL: http://scm-gy.tencent.com/gzrd/gzrd_mail_rep/QQMailcore_proj/trunk/comm2/core/base/string/iString.cpp $ $Id: iString.cpp 966846 2014-12-26 12:29:45Z stevenshe $ " GZRD_SVN_ATTR;
#endif
// gzrd_Lib_CPP_Version_ID--end

