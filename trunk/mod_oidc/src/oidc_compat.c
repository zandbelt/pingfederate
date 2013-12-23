
#define T_ESCAPE_URLENCODED    (64)

static const unsigned char test_c_table[256] = {
	32,126,126,126,126,126,126,126,126,126,127,126,126,126,126,126,126,126,126,126,
	126,126,126,126,126,126,126,126,126,126,126,126,14,64,95,70,65,102,65,65,
	73,73,1,64,72,0,0,74,0,0,0,0,0,0,0,0,0,0,104,79,
	79,72,79,79,72,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,79,95,79,71,0,71,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,79,103,79,65,126,118,118,118,118,118,118,118,118,118,118,118,118,
	118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
	118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
	118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
	118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
	118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
	118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118
};

#define TEST_CHAR(c, f)        (test_c_table[(unsigned)(c)] & (f))

static const char c2x_table[] = "0123456789abcdef";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
                                     unsigned char *where)
{
#if APR_CHARSET_EBCDIC
    what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}

static char x2c(const char *what)
{
	register char digit;

#if !APR_CHARSET_EBCDIC
	digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
			: (what[0] - '0'));
	digit *= 16;
	digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
			: (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
	char xstr[5];
	xstr[0]='0';
	xstr[1]='x';
	xstr[2]=what[0];
	xstr[3]=what[1];
	xstr[4]='\0';
	digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
			0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
	return (digit);
}

AP_DECLARE(char *) ap_escape_urlencoded_buffer(char *copy, const char *buffer) {
    const unsigned char *s = (const unsigned char *)buffer;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (TEST_CHAR(c, T_ESCAPE_URLENCODED)) {
            d = c2x(c, '%', d);
        }
        else if (c == ' ') {
            *d++ = '+';
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

static int oidc_session_unescape_url(char *url, const char *forbid, const char *reserved)
{
	register int badesc, badpath;
	char *x, *y;

	badesc = 0;
	badpath = 0;
	/* Initial scan for first '%'. Don't bother writing values before
	 * seeing a '%' */
	y = strchr(url, '%');
	if (y == NULL) {
		return OK;
	}
	for (x = y; *y; ++x, ++y) {
		if (*y != '%') {
			*x = *y;
		}
		else {
			if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
				badesc = 1;
				*x = '%';
			}
			else {
				char decoded;
				decoded = x2c(y + 1);
				if ((decoded == '\0')
						|| (forbid && ap_strchr_c(forbid, decoded))) {
					badpath = 1;
					*x = decoded;
					y += 2;
				}
				else if (reserved && ap_strchr_c(reserved, decoded)) {
					*x++ = *y++;
					*x++ = *y++;
					*x = *y;
				}
				else {
					*x = decoded;
					y += 2;
				}
			}
		}
	}
	*x = '\0';
	if (badesc) {
		return HTTP_BAD_REQUEST;
	}
	else if (badpath) {
		return HTTP_NOT_FOUND;
	}
	else {
		return OK;
	}
}

AP_DECLARE(int) ap_unescape_urlencoded(char *query) {
    char *slider;
    /* replace plus with a space */
    if (query) {
        for (slider = query; *slider; slider++) {
            if (*slider == '+') {
                *slider = ' ';
            }
        }
    }
    /* unescape everything else */
    return oidc_session_unescape_url(query, NULL, NULL);
}