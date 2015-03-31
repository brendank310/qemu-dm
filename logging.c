#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include "logging.h"

void logging_set_prefix(const char *ident)
{
    closelog();
    openlog(ident, LOG_NOWAIT | LOG_PID, LOG_DAEMON);
}

static inline void __syslog_vfprintf(const char *format, va_list ap)
{
    vsyslog(LOG_DAEMON | LOG_NOTICE, format, ap);
}

int qemu_log_vfprintf(FILE *stream, const char *format, va_list ap)
{
    __syslog_vfprintf(format, ap);

    return 0;
}

int qemu_log_printf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    __syslog_vfprintf(format, ap);

    return 0;
}

int qemu_log_fprintf(FILE *stream, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    __syslog_vfprintf(format, ap);

    return 0;
}
