#include "log_extract.h"
#include "jsonl.h"

int g_jsonl_enabled = 0;

/* JSON-escape s into out, return 0 on success, -1 on overflow */
static int jescape(const char *s, char *out, size_t outsz)
{
    size_t i = 0;
    if (!s) s = "";
    for (; *s && i + 6 < outsz; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"') { out[i++] = '\\'; out[i++] = '"'; }
        else if (c == '\\') { out[i++] = '\\'; out[i++] = '\\'; }
        else if (c == '\n') { out[i++] = '\\'; out[i++] = 'n'; }
        else if (c == '\r') { out[i++] = '\\'; out[i++] = 'r'; }
        else if (c == '\t') { out[i++] = '\\'; out[i++] = 't'; }
        else if (c < 0x20) {
            int n = snprintf(out + i, outsz - i, "\\u%04x", c);
            if (n < 0 || (size_t)n >= outsz - i) return -1;
            i += (size_t)n;
        } else {
            out[i++] = (char)c;
        }
    }
    if (*s) {
        /* truncate cleanly rather than fail — large message bodies are common */
        out[i] = '\0';
        return 0;
    }
    out[i] = '\0';
    return 0;
}

FILE *jsonl_open(const char *out_dir, const char *base_name)
{
    char path[MAX_PATH_LEN];
    char name[256];
    FILE *f;

    if (!g_jsonl_enabled) return NULL;
    if (!out_dir || !base_name) return NULL;

    snprintf(name, sizeof(name), "%s.jsonl", base_name);
    plat_path_join(path, sizeof(path), out_dir, name);
    f = fopen(path, "w");
    if (!f) {
        log_warn("jsonl: cannot open %s", path);
        return NULL;
    }
    return f;
}

void jsonl_emit(FILE *f, const char *source, time_t ts,
                int severity, const char *user, const char *message)
{
    char src_e[128];
    char user_e[256];
    char msg_e[MAX_LINE_LEN + 64];
    char ts_buf[32];

    if (!f || !g_jsonl_enabled) return;

    jescape(source ? source : "", src_e, sizeof(src_e));
    jescape(user ? user : "", user_e, sizeof(user_e));
    jescape(message ? message : "", msg_e, sizeof(msg_e));

    fputc('{', f);
    fprintf(f, "\"source\":\"%s\"", src_e);

    if (ts > 0) {
        plat_format_timestamp(ts, ts_buf, sizeof(ts_buf));
        fprintf(f, ",\"timestamp\":\"%s\"", ts_buf);
    }
    if (severity >= 0) {
        fprintf(f, ",\"severity\":%d", severity);
    }
    if (user_e[0]) {
        fprintf(f, ",\"user\":\"%s\"", user_e);
    }
    fprintf(f, ",\"message\":\"%s\"", msg_e);
    fputs("}\n", f);
}

void jsonl_close(FILE *f)
{
    if (f) fclose(f);
}
