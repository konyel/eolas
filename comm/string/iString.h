/**
@file
@brief 字符串相关函数
*/

#pragma once

#include <string>
#include <vector>
#include <limits.h>
#include <string.h>
#include <ctype.h>

#include "../iStdInt.h"
#include "../iPlatformFeatures.h"

using namespace std;

#define STR_IS_EMPTY(str)  ((NULL == (str) )||( '\0' == (str)[0]))
#define STR_GET_PRINT(str) ( STR_IS_EMPTY(str) ? "" : (str))
#define STR_GET_TEXT(str,deft) (STR_IS_EMPTY(str) ? (deft) : (str))
	
//对于为char*类型的数据进行的FUSE
#define STR_FUSE(rstr) Comm::CommStrFuseWord((NULL==(rstr) ? "-": (rstr))).c_str()
//对于为std::string类型的数据进行的FUSE
#define CSTR_FUSE(rstr) Comm::CommStrFuseWord( rstr )
// show word with ratio
#define STR_SHORT(rstr,...) Comm::CommStrShortWord( (NULL==(rstr) ? "-": (rstr)),##__VA_ARGS__).c_str()

#define BUFF_FUSE( buf ) \
	Comm::CommStrFuseWord(( (buf).size() == 0) ? "-": Comm::StrToHex( (buf).data(),((buf).size() > 8 ? 8:(buf).size()))).c_str()

#define HEX_FUSE( str ) \
	Comm::CommStrFuseWord( Comm::StrToHex( (NULL==(str) ? "": (str)))).c_str()

#define SKBUFF_FUSE( buf ) \
	Comm::CommStrFuseWord(( (buf).iLen == 0) ? "-": Comm::StrToHex( (buf).pcBuff,((buf).iLen > 8 ? 8:(buf).iLen))).c_str()

//typedef std::vector<string> TStringList;
//typedef std::string TString;
/// Comm库
namespace Comm
{
    typedef std::vector<string> TStringList;
    typedef std::string TString;


    inline bool memeql_2(const char* p1, const char* p2)
    {
        return *(uint16_t*)&p1[0] == *(uint16_t*)&p2[0];
    }

    inline bool memeql_3(const char* p1, const char* p2)
    {
        return
            *(uint16_t*)&p1[0] == *(uint16_t*)&p2[0] &&
            p1[2] == p2[2];
    }

    inline bool memeql_4(const char* p1, const char* p2)
    {
        return
            *(uint32_t*)&p1[0] == *(uint32_t*)&p2[0];
    }

    inline bool memeql_5(const char* p1, const char* p2)
    {
        return
            *(uint32_t*)&p1[0] == *(uint32_t*)&p2[0] &&
            p1[4] == p2[4];
    }

    inline bool memeql_6(const char* p1, const char* p2)
    {
        return
            *(uint32_t*)&p1[0] == *(uint32_t*)&p2[0] &&
            *(uint16_t*)&p1[4] == *(uint16_t*)&p2[4];
    }

    inline bool memeql_7(const char* p1, const char* p2)
    {
        return
            *(uint32_t*)&p1[0] == *(uint32_t*)&p2[0] &&
            *(uint16_t*)&p1[4] == *(uint16_t*)&p2[4] &&
            p1[6] == p2[6];
    }

    inline bool memeql_8(const char* p1, const char* p2)
    {
        return *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0];
    }

    inline bool memeql_9(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            p1[8] == p2[8];
    }

    inline bool memeql_10(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint16_t*)&p1[8] == *(uint16_t*)&p2[8];
    }

    inline bool memeql_11(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint16_t*)&p1[8] == *(uint16_t*)&p2[8] &&
            p1[10] == p2[10];
    }

    inline bool memeql_12(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint32_t*)&p1[8] == *(uint32_t*)&p2[8];
    }

    inline bool memeql_13(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint32_t*)&p1[8] == *(uint32_t*)&p2[8] &&
            p1[12] == p2[12];
    }

    inline bool memeql_14(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint32_t*)&p1[8] == *(uint32_t*)&p2[8] &&
            *(uint16_t*)&p1[12] == *(uint16_t*)&p2[12];
    }

    inline bool memeql_15(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint32_t*)&p1[8] == *(uint32_t*)&p2[8] &&
            *(uint16_t*)&p1[12] == *(uint16_t*)&p2[12] &&
            p1[14] == p2[14];
    }

    inline bool memeql_16(const char* p1, const char* p2)
    {
        return
            *(uint64_t*)&p1[0] == *(uint64_t*)&p2[0] &&
            *(uint64_t*)&p1[8] == *(uint64_t*)&p2[8];
    }

    // An optimized fast memory compare function, should be inlined
    inline bool memeql(const void* a1, const void* a2, size_t size)
    {
#if ALIGNMENT_INSENSITIVE_PLATFORM
        // optimize for alignment insensitive architectures
        const char* p1 = (const char*)a1;
        const char* p2 = (const char*)a2;

        switch (size)
        {
            case 0:
                return true;
            case 1:
                return p1[0] == p2[0];
            case 2:
                return memeql_2(p1, p2);
            case 3:
                return memeql_3(p1, p2);
            case 4:
                return memeql_4(p1, p2);
            case 5:
                return memeql_5(p1, p2);
            case 6:
                return memeql_6(p1, p2);
            case 7:
                return memeql_7(p1, p2);
            case 8:
                return memeql_8(p1, p2);
            case 9:
                return memeql_9(p1, p2);
            case 10:
                return memeql_10(p1, p2);
            case 11:
                return memeql_11(p1, p2);
            case 12:
                return memeql_12(p1, p2);
            case 13:
                return memeql_13(p1, p2);
            case 14:
                return memeql_14(p1, p2);
            case 15:
                return memeql_15(p1, p2);
            case 16:
                return memeql_16(p1, p2);
        }

        while (size >= 8)
        {
            if (*(uint64_t*)&p1[0] != *(uint64_t*)&p2[0])
                return false;
            p1 += 8;
            p2 += 8;
            size -= 8;
        }
        if (size >= 4)
        {
            if (*(uint32_t*)&p1[0] != *(uint32_t*)&p2[0])
                return false;
            p1 += 4;
            p2 += 4;
            size -= 4;
        }
        if (size >= 2)
        {
            if (*(uint16_t*)&p1[0] != *(uint16_t*)&p2[0])
                return false;
            p1 += 2;
            p2 += 2;
            size -= 2;
        }
        if (size == 1)
            return p1[0] == p2[0];

        return true;
#else
        return memcmp(a1, a2, size) == 0;
#endif
    }

    inline int memcasecmp (const void *vs1, const void *vs2, size_t n)
    {
        size_t i;
        const unsigned char *s1 = static_cast<const unsigned char*>(vs1);
        const unsigned char *s2 = static_cast<const unsigned char*>(vs2);
        for (i = 0; i < n; i++)
        {
            unsigned char u1 = s1[i];
            unsigned char u2 = s2[i];
            int U1 = toupper(u1);
            int U2 = toupper(u2);
            int diff = (UCHAR_MAX <= INT_MAX ? U1 - U2
                    : U1 < U2 ? -1 : U2 < U1);
            if (diff)
                return diff;
        }
        return 0;
    }


    enum TECharSet{csGBK,csUTF8,csGB18030};

    /**
     * @brief 查找目标字符在源字符串中出现的位置
     * @param pcSrc 源字符串
     * @param cFind 查找字符
     * @param nStart 在源字符串中的开始位置
     * @param bCaseSensitive 是否大小写敏感
     * @retval 查找到的位置，-1表示没找到
     * @as testString.cpp
     */
    int StrFind(const char* pcSrc, char cFind, int nStart = 0, bool bCaseSensitive = true);

    /**
     * @brief 查找目标字符串在源字符串中出现的位置
     * @param pcSrc 源字符串
     * @param pcFind 查找字符串
     * @param nStart 在源字符串中的开始位置
     * @param bCaseSensitive 是否大小写敏感
     * @retval 查找到的位置，-1表示没找到
     * @as testString.cpp
     */
    int StrFind(const char* pcSrc, const char* pcFind, int nStart = 0, bool bCaseSensitive = true);

    /**
     * @brief 查找目标字符串中的任意字符在源字符串中首先出现的位置，例如pcSrc="abcd", pcFind="cb", 那么则返回1（b首先出现在位置1）
     * @param pcSrc 源字符串
     * @param pcFind 查找字符串
     * @param nStart 在源字符串中的开始位置
     * @param bCaseSensitive 是否大小写敏感
     * @retval 查找到的位置，-1表示没找到
     * @as testString.cpp
     */
    int StrFindFirstOf(const char* pcSrc, const char* pcFind, int nStart = 0, bool bCaseSensitive = true);

    /**
     * @brief 去掉字符串前后中出现的字符。
     * @param pcSrc 源字符串
     * @param pcTrim 需要去掉的字符列表，默认为' ','\\t','\\r','\\n'。
     * @as testString.cpp
     */
    void StrTrim(char* pcSrc, const char* pcTrim = " \t\r\n");

    /**
     * @brief 去掉字符串前后中出现的字符。
     * @param[in,out] sSrc 源字符串
     * @param sTrim 需要去掉的字符列表，默认为' ','\\t','\\r','\\n'。
     * @as testString.cpp
     */
    void StrTrim(std::string& sSrc, const std::string& sTrim = " \t\r\n");

    /**
     * @brief 把字符串中的字母转换为大写。
     * @param[in,out] pcSrc 源字符串
     */
    void StrUpper(char* pcSrc);

    /**
     * @brief 把字符串中的字母转换为大写。
     * @param[in,out] sSrc 源字符串
     */
    void StrUpper(std::string& sSrc);

    /**
     * @brief 把字符串中的字母转换为小写。
     * @param[in,out] pcSrc 源字符串
     */
    void StrLower(char* pcSrc);

    /**
     * @brief 把字符串中的字母转换为小写。
     * @param[in,out] sSrc 源字符串
     */
    void StrLower(std::string& sSrc);

    /**
     * @brief 字符串copy。
     * @param[out] pcDst 目标字符串，会在结尾补\\0。
     * @param pcSrc 源字符串。
     * @param nDstLen 目标字符串允许的长度(实际copy的长度为nDstLen-1，最后一个字符为\\0)。
     */
    void StrnCpy(char* pcDst, const char* pcSrc, int nDstLen);

    /**
     * @brief 字符串串接
     * @param[out] pcDst 目标字符串，会在结尾补\\0。
     * @param pcSrc 源字符串。
     * @param nDstLen 目标字符串允许的长度(实际copy的长度为nDstLen-1，最后一个字符为\\0)。
     * @retval 目的串
     */
    char* StrnCat(char* pcDst, const char* pcSrc, int nDstLen);

    /**
     * @brief 字符串比较。
     * @param pcStr1 字符串1。
     * @param pcStr2 字符串2。
     * @param bCaseSensitive 是否大小写敏感。
     * @retval <0表示pcStr1<pcStr2; ==0表示pcStr1==pcStr2; >0表示pcStr1>pcStr2。
     */
    int StrCmp(const char* pcStr1, const char* pcStr2, bool bCaseSensitive = true);

    /**
     * @brief 字符串比较（指定比较的长度）。
     * @param pcStr1 字符串1。
     * @param pcStr2 字符串2。
     * @param nLen 需要比较的长度
     * @param bCaseSensitive 是否大小写敏感。
     * @retval <0表示pcStr1<pcStr2; ==0表示pcStr1==pcStr2; >0表示pcStr1>pcStr2。
     */
    int StrnCmp(const char* pcStr1, const char* pcStr2, int nLen, bool bCaseSensitive = true);

    /**
     * @brief 字符串是否相等。
     * @param pcStr1 字符串1。
     * @param pcStr2 字符串2。
     * @param bCaseSensitive 是否大小写敏感。
     * @retval 是否相等。
     */
    bool StrEqual(const char* pcStr1, const char* pcStr2, bool bCaseSensitive = true);

    /*!
     * \brief Compare two strings for equality, ignoring case.
     *
     * For case-sensitive comparison, use (s1 == s2);
     * \param s1 The first string to compare
     * \param s2 The second string to compare
     * \return \c true if the strings are equal, \c false if they are not
     */
    bool stringsAreEqual(const std::string& s1,const std::string& s2);

    /*!
     * \brief Compare two strings for equality, ignoring case.
     *
     * For case-sensitive comparison, use (s1 == s2);
     * \param s1 The first string to compare
     * \param s2 The second string to compare
     * \param n The number of characters to compare.
     * \return \c true if the strings are equal, \c false if they are not
     */
    bool stringsAreEqual(const std::string& s1,const std::string& s2,size_t n);

    /**
     * @brief 根据分隔符分割字符串，返回分割后的字符串列表。
     * @param pcStr 源字符串
     * @param pcDelimiter 分隔符串
     * @param bFullCheck 表示delimiter是完全匹配还是只匹配里面的某一个字符
     * @param[out] vecResult 分割后的字符串列表
     * @as testString.cpp
     */
    void StrSplitList(const char* pcStr, const char* pcDelimiter, bool bFullCheck, std::vector<std::string>& vecResult);

    /// 根据分隔符分割字符串，支持""内的字符串不进行分割。（原stroper.hpp中的gpcParseString）
    /**
     * 例：()				-> NULL NULL  			\n
     *     ("")				-> () NULL  			\n
     *     (abc)			-> (abc) NULL  			\n
     *     (a b c)			-> (a) (b) (c) NULL  	\n
     *     ("a b" c)		-> (a b) (c) NULL  		\n
     *     ("a b"c d)   	-> (a bc) (d) NULL  	\n
     *     ("\"a b\""c d)	-> ("a b"c) (d) NULL	\n
     * @param[out] pcResult 结果字符串，分割后的字符串存放在这里。
     * @param nResultLen 结果字符串的长度
     * @param pcSrc 源字符串
     * @param nIndex 取分割后的第几个字符串，从0开始。
     * @param[out] ppcNext 当前分割后的下一个字符位置
     * @param cDelimiter 分隔符，默认为' '或'\\t'或'\\r'或'\\n'
     * @retval 返回结果字符串位置
     * @as testString.cpp
     */
    const char* StrQuotedSplit(char* pcResult, int nResultLen, const char* pcSrc, int nIndex,
            const char** ppcNext = NULL, char cDelimiter = 0);

    /**
     * @brief 把被左和右字符括住的字符串位置返回
     * @param pcStr 源字符串
     * @param cLeftEnclose 左括字符
     * @param cRightEnclose 右括字符
     * @param[out] pnLen 括住字符串的长度
     * @retval 括住的字符串在pcStr中的地址，NULL表示没有对应的字符串。
     * @as testString.cpp
     */
    const char* StrEnclose(const char* pcStr, char cLeftEnclose, char cRightEnclose, int* pnLen);

    /**
     * @brief 把被左和右字符括住的字符串位置返回
     * @param pcStr 源字符串
     * @param cLeftEnclose 左括字符
     * @param cRightEnclose 右括字符
     * @retval 括住的字符串
     * @as testString.cpp
     */
    std::string StrEnclose(const char* pcStr, char cLeftEnclose, char cRightEnclose);

    /**
     * @brief Verfiy if the content of string is integer.
     * @param sString: Input string.
     * @return 0=OK, 1=FAIL
     */
    int StrIsInteger(const char *sString);

    /**
     * @brief 格式化字符串
     * @param pcFmt 格式串
     * @retval 格式化后的字符串
     */
    std::string StrFormat(const char* pcFmt, ...)
        __attribute__((format(printf, 1, 2)));

    /**
     * @brief 格式化字符串
     * @param sStr 格式化后的字符串
     * @param pcFmt 格式串
     */
    void StrFormat(std::string& sStr, const char* pcFmt, ...)
        __attribute__((format(printf, 2, 3)));

    /*!
     * \brief Extract a substring contained within two separators.
     *
     * extractBetween("eelllllabcdefgrrrrrree", "ll", "rr"), get the result is "lllabcdefg";
     * For example, after the call
     * \code
     * std::string data = "11foo22";
     * std::string res;
     * res = extractBetween(data, "11", "22");
     * \endcode
     * \c res will be "foo".
     * \param data The data to search.
     * \param separator1 The first logical separator.
     * \param separator2 The second logical separator.
     * \return The substring between the separators.
     * \as testString.cpp
     */
    std::string extractBetween(const std::string& data,const std::string& separator1,const std::string& separator2);

    char * extractBetween(char *pData,const char* separator1,const char* separator2);
    char * extractBetween(char *pData,char* separator1,char* separator2);

    /*!
     * \brief  在 pDst 搜索 pPat。
     *
     * \param	pDst: the memory to search
     * \param	pPat: search pattern
     * \param	nDstLen: length of pDst
     * \param	nPatLen: length of pPat
     *
     * \return return NULL if pPat not in pDst, else return the start position match pPat in pDst
     */
    char* MemSearch(char *pDst, char *pPat, int nDstLen, int nPatLen);



    const char * ParseString ( register char *asResult, int aiResultSize,
            const char *asSource,  int aiIndex, const char ** lpcNext = (const char **)0, char acDelimitor = 0 ) ;

    int IsSpace ( register int c ) ;
    int IsAlnum ( register int c ) ;
    int IsDigit ( register int c ) ;
    int IsAlpha ( register int c ) ;

    int StringToBitmap(const char *asString,char *pBitsBuff,size_t nBuffSize);
    string BitmapToString(char *pBitsBuff,size_t nBitCount);

    void StrReplaceAll( string & haystack, string needle, string s );

    unsigned long int StringHash(
            register char *k,            /* the key */
            register unsigned long  int length,   /* the length of the key */
            register unsigned long  int initval   /* the previous hash, or an arbitrary value */
            );

    string Left(const string & sStr,int nCount);

    string Right(const string &sStr, int nCount);

    string AllTrim(const string &sStr,const string & sToTrim=" ");

    string LeftTrim(const string &sStr,const string & sToTrim=" ");

    string RightTrim(const string &sStr,const string & sToTrim=" ");

    int StrToInt(const string &sStr);

    unsigned int StrToUInt(const string &sStr);

    long long int StrToLLInt(const string &sStr);

    unsigned int BufferToUInt(const char *psz);

    string Mid(const string & sStr,long lBegin);

    string Mid(const string & sStr,long lBegin,long lCount );

    string IntToStr(const int i);

    string UIntToStr(const unsigned int i);

    string LLIntToStr(const long long int i);

    string ULLIntToStr(const unsigned long long int i);

    string Padl(const string & sStr,unsigned long lCount,char ch);

    int SeparateText(vector<string> &slStringList,const string &sStr,const char cSeparator);

    //==========================================================================
    // 函数 : BCBToStr
    // 用途 : 将BCB码转换为数字字符串编码
    // 原型 : TCString BCBToStr(const TCString & sBCBStr);
    // 参数 : BCB串
    // 返回 : 数字字符串
    // 说明 :
    //    原串: "\x13\x29\x38\x76"
    //    结果: "13293876"
    //==========================================================================
    int BCBToStr(const char * szBCBStr,char * szStr);

    //==========================================================================
    // 函数 : StrToBCB
    // 用途 : 将数字字符串转换为BCB码
    // 原型 : TCString StrToBCB(const TCString & sNumStr);
    // 参数 : 数字字符串
    // 返回 : BCB编码字符串
    // 说明 :
    //    原串: "13293876"
    //    结果: "\x13\x29\x38\x76"
    //==========================================================================
    int StrToBCB(const char * szNumStr,char * szStr);

    //字符串匹配函数 limq 2005-4-13
    //可以匹配*?为通配符的字符串:*表示0或多个任意字符,?表示1个任意字符
    //按照最长字串匹配算法,可以支持相连的两或多个**号,*?等,目前为止,我暂时没有发现有什么局限性.
    bool FilterStr(const string &sStr,const string &sFilter);
    bool FilterStr(const char  * const str,const char * const filter);

    bool IsUpperAlphabetString(const string & sStr);

    bool IsNumber(const string & sStr);

    bool IsNumber(const char * psz);

    //是否浮点数，整数也是是浮点数
    bool IsFloat(const string & sStr);

    bool IsFloat(const char * psz);

    string Replace(const string& sStr,const string sToFind,const string &sReplaceWith);

    bool IsAsciiStr(const string & sStr);

    string NumericCharacterEntities(string sStr, const string sSearchWord, const int nBase, char cEndChar='\0');

    string ToLowerCase(const string & sSrc);

    string ToUpperCase(const string & sSrc);

    string GetSeperatedTextByIndex(const string &sStr,const int nIndex,const string & sSeparatorList);

    string GetNext(const string & sStr,size_t & nStartPos,const TECharSet emCharSet);

    string StrToHex(const string & sStr);

    string StrToHex( const char * sSrc, size_t len );

    unsigned char HexToByte(char c);

    string HexToStr(const string &sHex);

    string LogPrefix(const char* pcFile,const int iLen ,const char *pcFunc);

    const std::string CommStrFuseWord(const string& sBuf);
    const std::string CommStrShortWord(const std::string& sData, float fRatio=0.5);
    void DeviceId2Uuid(const unsigned char *cDeviceID, string &sUuid);

    void * MemDup( const void * ptr, size_t len );
}

