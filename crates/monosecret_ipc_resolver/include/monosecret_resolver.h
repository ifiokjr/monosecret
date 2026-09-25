#ifndef MONOSECRET_RESOLVER_H
#define MONOSECRET_RESOLVER_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(MONOSECRET_RESOLVER_SHARED)
#  if defined(MONOSECRET_RESOLVER_BUILDING)
#    define MONOSECRET_RESOLVER_API __declspec(dllexport)
#  else
#    define MONOSECRET_RESOLVER_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define MONOSECRET_RESOLVER_API __attribute__((visibility("default")))
#else
#  define MONOSECRET_RESOLVER_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MONOSECRET_RESOLVER_ABI_VERSION ((1u << 16) | 0u)

typedef struct monosecret_resolver_client monosecret_resolver_client;
typedef struct monosecret_resolver_call monosecret_resolver_call;
typedef struct monosecret_resolver_prompt monosecret_resolver_prompt;

typedef struct {
    const unsigned char *data;
    size_t size;
} monosecret_resolver_slice;

enum {
    /* Resolve a bare executable name against PATH. On Windows only absolute
     * PATH entries are searched, never the application or current directory,
     * and only .exe and .com files resolve; name a script shim by its full
     * path. */
    MONOSECRET_RESOLVER_DISCOVER_EXECUTABLE = 1u << 0,
    MONOSECRET_RESOLVER_INHERIT_ENVIRONMENT = 1u << 1,
    /* Advertise that this client can obtain a secret value from a person, so
     * the endpoint may ask it to (0.4.0+). The library adds the capability to
     * the initialization it sends; do not put client_methods in
     * initialize_params_json yourself.
     *
     * A session with this flag answers prompts through
     * monosecret_resolver_prompt_take and monosecret_resolver_prompt_answer, and its
     * calls must be driven with monosecret_resolver_call_start and
     * monosecret_resolver_call_wait rather than monosecret_resolver_client_call, which
     * has no handle to resume after a prompt. */
    MONOSECRET_RESOLVER_ANSWER_PROMPTS = 1u << 2
};

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t reserved;
    monosecret_resolver_slice executable;
    const monosecret_resolver_slice *arguments;
    size_t argument_count;
    const monosecret_resolver_slice *environment;
    size_t environment_count;
    monosecret_resolver_slice initialize_params_json;
    size_t max_stderr_bytes;
} monosecret_resolver_options;

typedef enum {
    MONOSECRET_RESOLVER_OK = 0,
    MONOSECRET_RESOLVER_INVALID_ARGUMENT = 1,
    MONOSECRET_RESOLVER_UNAVAILABLE = 2,
    MONOSECRET_RESOLVER_IO = 3,
    MONOSECRET_RESOLVER_PROTOCOL = 4,
    MONOSECRET_RESOLVER_REMOTE_ERROR = 5,
    MONOSECRET_RESOLVER_CANCELLED = 6,
    MONOSECRET_RESOLVER_DEADLINE_EXCEEDED = 7,
    /* A call cannot finish until a prompt is answered (0.4.0+). Take it with
     * monosecret_resolver_prompt_take, answer or decline it, then wait again. Only
     * a session opened with MONOSECRET_RESOLVER_ANSWER_PROMPTS can see this. */
    MONOSECRET_RESOLVER_PROMPT_PENDING = 8
} monosecret_resolver_status;

typedef struct {
    unsigned char *data;
    size_t size;
} monosecret_resolver_buffer;

MONOSECRET_RESOLVER_API uint32_t monosecret_resolver_abi_version(void);

MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_client_open(
    const monosecret_resolver_options *options,
    uint64_t deadline_unix_ms,
    monosecret_resolver_client **client,
    monosecret_resolver_buffer *server_info,
    monosecret_resolver_buffer *error);

MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_call_start(
    monosecret_resolver_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    monosecret_resolver_call **call,
    monosecret_resolver_buffer *error);

/* Convenience form for callers that do not need cancellation or multiplexing. */
MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_client_call(
    monosecret_resolver_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    monosecret_resolver_buffer *result,
    monosecret_resolver_buffer *error);

MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_call_wait(
    monosecret_resolver_call *call,
    monosecret_resolver_buffer *result,
    monosecret_resolver_buffer *error);

MONOSECRET_RESOLVER_API void monosecret_resolver_call_cancel(monosecret_resolver_call *call);
MONOSECRET_RESOLVER_API void monosecret_resolver_call_free(monosecret_resolver_call *call);

/* Prompts (0.4.0+).
 *
 * The endpoint asks this client for a value only when the session advertised
 * MONOSECRET_RESOLVER_ANSWER_PROMPTS. There is deliberately no callback: a binding
 * for another language must not have to hand a C function pointer to a foreign
 * runtime, so the answer is driven by the caller instead.
 *
 * The loop is:
 *
 *   status = monosecret_resolver_call_wait(call, &result, &error);
 *   while (status == MONOSECRET_RESOLVER_PROMPT_PENDING) {
 *       monosecret_resolver_prompt *prompt = NULL;
 *       if (monosecret_resolver_prompt_take(client, &prompt, &error)) break;
 *       ... read a value from the person, using monosecret_resolver_prompt_params ...
 *       monosecret_resolver_prompt_answer(prompt, value, value_size, &error);
 *       monosecret_resolver_prompt_free(prompt);
 *       status = monosecret_resolver_call_wait(call, &result, &error);
 *   }
 *
 * A prompt belongs to the session, not to one call, so any waiting call may be
 * the one that surfaces it. Every taken prompt must be answered or declined:
 * one left unanswered blocks the endpoint until its deadline elapses. */

/* Take the prompt the endpoint is waiting on. Sets *prompt to NULL and returns
 * OK when none is pending. */
MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_prompt_take(
    monosecret_resolver_client *client,
    monosecret_resolver_prompt **prompt,
    monosecret_resolver_buffer *error);

/* The prompt's parameters as JSON: the declared name, the profile, and the
 * credential-free provider URI the answer will be stored at, if any. Borrowed
 * from the prompt and valid until it is freed. */
MONOSECRET_RESOLVER_API monosecret_resolver_slice monosecret_resolver_prompt_params(
    const monosecret_resolver_prompt *prompt);

/* Answer with the value a person supplied. It is a secret: the library clears
 * its own copy after writing, and the caller should clear the buffer it owns.
 * An empty value is refused; decline instead. So is an answer too large for
 * the negotiated frame size: the prompt stays open, so it can still be
 * declined. */
MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_prompt_answer(
    monosecret_resolver_prompt *prompt,
    const unsigned char *value,
    size_t value_size,
    monosecret_resolver_buffer *error);

/* Refuse the prompt. The resolution that raised it fails as
 * interaction_required rather than waiting out its deadline. */
MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_prompt_decline(
    monosecret_resolver_prompt *prompt,
    monosecret_resolver_buffer *error);

MONOSECRET_RESOLVER_API void monosecret_resolver_prompt_free(monosecret_resolver_prompt *prompt);

/* Close the session. Prompts nobody has taken are declined first, because the
 * endpoint cannot finish draining its work while it waits on one. */
MONOSECRET_RESOLVER_API monosecret_resolver_status monosecret_resolver_client_close(
    monosecret_resolver_client *client,
    uint64_t deadline_unix_ms,
    monosecret_resolver_buffer *error);

MONOSECRET_RESOLVER_API void monosecret_resolver_client_free(monosecret_resolver_client *client);
MONOSECRET_RESOLVER_API void monosecret_resolver_buffer_free(monosecret_resolver_buffer buffer);

#ifdef __cplusplus
}
#endif

#endif
