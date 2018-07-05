/* liblouis Braille Translation and Back-Translation  Library

   Copyright (C) 2004, 2005, 2006 ViewPlus Technologies, Inc. www.viewplus.com
   Copyright (C) 2004, 2005, 2006 JJB Software, Inc. www.jjb-software.com

   This file is part of liblouis.

   liblouis is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation, either version 2.1 of the License, or
   (at your option) any later version.

   liblouis is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with liblouis. If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file
 * @brief Logging
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "internal.h"

void EXPORT_CALL
_lou_logWidecharBuf(logLevels level, const char *msg, const widechar *wbuf, int wlen) {
	/* When calculating output size:
	 * Each wdiechar is represented in hex, thus needing two bytes for each
	 * byte in the widechar (sizeof(widechar) * 2)
	 * Allow space for the "0x%X " formatting (+ 3)
	 * Number of characters in widechar buffer (wlen * )
	 * Give space for additional message (+ strlen(msg))
	 * Remember the null terminator (+ 1)
	 */
	int logBufSize = (wlen * ((sizeof(widechar) * 3) + 3)) + 3 + (int)strlen(msg);
	char *logMsg = malloc(logBufSize);
	char *p = logMsg;
	char *formatString;
	int i = 0;
	if (sizeof(widechar) == 2)
		formatString = "0x%04X ";
	else
		formatString = "0x%08X ";
	for (i = 0; i < (int)strlen(msg); i++) logMsg[i] = msg[i];
	p += strlen(msg);
	for (i = 0; i < wlen; i++) {
		p += sprintf(p, formatString, wbuf[i]);
	}
	*p = '~';
	p++;
	*p = ' ';
	p++;
	for (i = 0; i < wlen; i++) {
		if (wbuf[i] & 0xff00)
			*p = ' ';
		else
			*p = (char)wbuf[i];
		p++;
	}
	*p = '\0';
	_lou_logMessage(level, "%s", logMsg);
	free(logMsg);
}

static void
defaultLogCallback(logLevels level, const char *message) {
	lou_logPrint("%s",
			message);  // lou_logPrint takes formatting, protect against % in message
}

static logcallback logCallbackFunction = defaultLogCallback;
void EXPORT_CALL
lou_registerLogCallback(logcallback callback) {
	if (callback == NULL)
		logCallbackFunction = defaultLogCallback;
	else
		logCallbackFunction = callback;
}

static logLevels logLevel = LOG_INFO;
void EXPORT_CALL
lou_setLogLevel(logLevels level) {
	logLevel = level;
}

void EXPORT_CALL
_lou_logMessage(logLevels level, const char *format, ...) {
	if (format == NULL) return;
	if (level < logLevel) return;
	if (logCallbackFunction != NULL) {
#ifdef _WIN32
		double f = 2.3;  // Needed to force VC++ runtime floating point support
#endif
		char *s;
		size_t len;
		va_list argp;
		va_start(argp, format);
		len = vsnprintf(0, 0, format, argp);
		va_end(argp);
		if ((s = malloc(len + 1)) != 0) {
			va_start(argp, format);
			vsnprintf(s, len + 1, format, argp);
			va_end(argp);
			logCallbackFunction(level, s);
			free(s);
		}
	}
}

static FILE *logFile = NULL;
static char initialLogFileName[256] = "";

void EXPORT_CALL
lou_logFile(const char *fileName) {
	if (logFile) {
		fclose(logFile);
		logFile = NULL;
	}
	if (fileName == NULL || fileName[0] == 0) return;
	if (initialLogFileName[0] == 0) strcpy(initialLogFileName, fileName);
	logFile = fopen(fileName, "a");
	if (logFile == NULL && initialLogFileName[0] != 0)
		logFile = fopen(initialLogFileName, "a");
	if (logFile == NULL) {
		fprintf(stderr, "Cannot open log file %s\n", fileName);
		logFile = stderr;
	}
}

void EXPORT_CALL
lou_logPrint(const char *format, ...) {
#ifndef __SYMBIAN32__
	va_list argp;
	if (format == NULL) return;
	if (logFile == NULL) logFile = fopen(initialLogFileName, "a");
	if (logFile == NULL) logFile = stderr;
	va_start(argp, format);
	vfprintf(logFile, format, argp);
	fprintf(logFile, "\n");
	fflush(logFile);
	va_end(argp);
#endif
}

/* Close the log file */
void EXPORT_CALL
lou_logEnd ()
{
  closeLogFile();
}

void closeLogFile()
{
  if (logFile != NULL && logFile != stderr)
    fclose (logFile);
  logFile = NULL;
}


static FILE *output = NULL;

void out_init(void)
{
	if(!output)
		output = fopen("liblouis-output.txt", "w");
}

void out_message(const char *msg)
{
	if(!output)
		return;
	if(!msg)
		return;

	fprintf(output, "%s\n", msg);
	fflush(output);
}

int is_wchar_containing(const widechar *wbuf, int wlen, const char *sub)
{
	int i;

	if(!output)
		return 0;
	if(!wbuf)
		return 0;
	if(!sub)
		return 0;

	int logBufSize = (wlen * 2);
	char *logMsg = malloc(logBufSize);
	char *p = logMsg;
	for(i = 0; i < wlen; i++)
	{
		if(wbuf[i] & 0xff00)
			*p = ' ';
		else
			*p = (char)wbuf[i];
		p++;
	}
	*p = '\0';

	if(strstr(logMsg, sub))
	{
		free(logMsg);
		return 1;
	}
	else
	{
		free(logMsg);
		return 0;
	}
}

void out_wchar(const widechar *wbuf, int wlen)
{
	int i;

	if(!output)
		return;

	if(!wbuf)
	{
//		fprintf(output, ">><><<");
//		fflush(output);
		return;
	}

//	fprintf(output, ">> ");

	int logBufSize = (wlen * 2);
	char *logMsg = malloc(logBufSize);
	char *p = logMsg;

	for(i = 0; i < wlen; i++)
	{
		if(wbuf[i] & 0xff00)
			*p = '-';
		else
			*p = (char)wbuf[i];
		p++;
	}
	*p = '\0';
	fprintf(output, "%s", logMsg);
//	fprintf(output, "%s <>", logMsg);

//	for(i = 0; i < wlen; i++)
//		fprintf(output, " %x", wbuf[i]);

//	fprintf(output, " <<");

	fprintf(output, "\n");
	fflush(output);
	free(logMsg);
}

void out_wchar_hex(const widechar *wbuf, const int wlen)
{
	int i;

	if(!output)
		return;

	if(!wbuf)
		return;

	for(i = 0; i < wlen; i++)
	{
		if(wbuf[i] < 32 || wbuf[i] > 127)
			fprintf(output, "_ %x  ", wbuf[i]);
		else
			fprintf(output, "%c %x  ", wbuf[i], wbuf[i]);
	}
	fprintf(output, "\n");
	fflush(output);
}

static void out_emphasis(const formtype *typeform, int wlen, const formtype bit, const char emp, char *buf)
{
	int i;
	char *p = buf;
	for(i = 0; i < wlen; i++)
	{
		if(typeform[i] & bit)
			*p = emp;
		else
			*p = ' ';
		p++;
	}
	*p = '\0';
	fprintf(output, "%s\n", buf);
}

void out_wchar_emphases(const formtype *typeform, const widechar *wbuf, int wlen)
{
#if 0
	int i, emps;

	if(!output)
		return;

	if(!typeform)
	{
		out_wchar(wbuf, wlen);
		fflush(output);
		return;
	}

	//fprintf(output, "]] ");

	int logBufSize = (wlen * 2);
	char *logMsg = malloc(logBufSize);

	emps = 0;
	for(i = 0; i < wlen; i++)
		emps |= typeform[i];

	if(emps)
	{
		fprintf(output, "~emp\n");
		if(emps & bold)
			out_emphasis(typeform, wlen, bold, 'b', logMsg);
		if(emps & italic)
			out_emphasis(typeform, wlen, italic, 'i', logMsg);
		if(emps & underline)
			out_emphasis(typeform, wlen, underline, 'u', logMsg);
		if(emps & script)
			out_emphasis(typeform, wlen, script, 's', logMsg);
		if(emps & trans_note)
			out_emphasis(typeform, wlen, trans_note, 'n', logMsg);
		if(emps & trans_note_1)
			out_emphasis(typeform, wlen, trans_note_1, '1', logMsg);
		if(emps & trans_note_2)
			out_emphasis(typeform, wlen, trans_note_2, '2', logMsg);
		if(emps & trans_note_3)
			out_emphasis(typeform, wlen, trans_note_3, '3', logMsg);
		if(emps & trans_note_4)
			out_emphasis(typeform, wlen, trans_note_4, '4', logMsg);
		if(emps & trans_note_5)
			out_emphasis(typeform, wlen, trans_note_5, '5', logMsg);
		if(emps & computer_braille)
			out_emphasis(typeform, wlen, computer_braille, 'c', logMsg);
		if(emps & passage_break)
			out_emphasis(typeform, wlen, passage_break, '|', logMsg);
		if(emps & word_reset)
			out_emphasis(typeform, wlen, word_reset, '-', logMsg);
	}

	//fprintf(output, " [[\n");

	out_wchar(wbuf, wlen);
	fflush(output);
	free(logMsg);
#endif
}

void out_wchar_containing(const widechar *wbuf, int wlen, const char *sub)
{
	int i;

	if(!output)
		return;
	if(!wbuf)
		return;

	int logBufSize = (wlen * 2);
	char *logMsg = malloc(logBufSize);
	char *p = logMsg;
	for(i = 0; i < wlen; i++)
	{
		if(wbuf[i] & 0xff00)
			*p = ' ';
		else
			*p = (char)wbuf[i];
		p++;
	}
	*p = '\0';
	if(sub)
	{
		if(!strstr(logMsg, sub))
		{
			free(logMsg);
			return;
		}
	}
	fprintf(output, "%s\n", logMsg);
	fflush(output);
	free(logMsg);
}

void out_rule(const TranslationTableRule *rule, const char *opcode)
{
	const char *str;
	
	if(!output)
		return;
	if(!rule)
	{
		fprintf(output, "direct\t\t'%c'\n", *opcode);
		return;
	}

	if(opcode)
		str = opcode;
	else
		str = _lou_findOpcodeName(rule->opcode);
	fprintf(output, "%s", str);
	if(strlen(str) < 8)
		fputs("\t", output);

	switch(rule->opcode)
	{
	case CTO_Pass2:
	case CTO_Pass3:
	case CTO_Pass4:
	
		str = _lou_showDots(rule->charsdots, rule->charslen);
		break;
	
	default:
	
		str = _lou_showString(rule->charsdots, rule->charslen);
		break;
	}
	fprintf(output, "\t%s", str);
	
	str = _lou_showDots(&rule->charsdots[rule->charslen], rule->dotslen);
	fprintf(output, "\t%s\n", str);
}

#define WORD_CHAR         0x00000001
#define WORD_RESET        0x00000002
#define WORD_STOP         0x00000004
#define WORD_WHOLE        0x00000008
#define LAST_WORD_AFTER   0x01000000

void out_words(const int *buf, const int wlen)
{
	int i;

	//for(i = 0; i < wlen; i++)
	//	fprintf(output, "%x ", buf[i]);
	//fprintf(output, "\n");
	
	int logBufSize = (wlen * 2);
	char *logMsg = malloc(logBufSize);
	char *p = logMsg;
	for(i = 0; i < wlen; i++)
	{
		*p = ' ';
		if(buf[i] & WORD_CHAR)
			*p = 'w';
		if(buf[i] & WORD_WHOLE)
			*p = 'W';
		p++;
	}
	
	*p = '\0';
	fprintf(output, "%s\n", logMsg);
	fflush(output);
	free(logMsg);
}

void out_emps_buffer(const int *buf, int wlen)
{
	if(!buf)
		return;

	int i;
	for(i = 0; i < wlen; i++)
		fprintf(output, "%x ", buf[i]);
	fprintf(output, "\n");
}

void out_typeforms(const formtype *buf, int wlen)
{
	if(!buf)
		return;

	int i;
	for(i = 0; i < wlen; i++)
		fprintf(output, "%x ", buf[i]);
	fprintf(output, "\n");
}
