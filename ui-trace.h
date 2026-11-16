#ifndef AFLNET_UI_TRACE_H
#define AFLNET_UI_TRACE_H

/* Bounded, opt-in telemetry from the fuzzer, never from the target process. */
#define UI_TRACE_FILE_LIMIT (1024 * 1024)
#define UI_TRACE_PREVIEW 512
static FILE *ui_trace_file;
static u8 ui_trace_initialized, ui_trace_enabled, ui_trace_connection_failed;
static u64 ui_trace_sequence, ui_trace_case;
static u8 *ui_trace_path, *ui_trace_previous;

static void ui_trace_string(const u8 *value) {
  fputc('"', ui_trace_file);
  if (value) for (; *value; value++) {
    if (*value == '"' || *value == '\\') fprintf(ui_trace_file, "\\%c", *value);
    else if (*value < 32) fprintf(ui_trace_file, "\\u%04x", *value);
    else fputc(*value, ui_trace_file);
  }
  fputc('"', ui_trace_file);
}

static u8 ui_trace_open(void) {
  if (!ui_trace_initialized) {
    ui_trace_initialized = 1;
    ui_trace_enabled = use_net && env_flag_enabled("AFLNET_UI_TRACE");
    if (ui_trace_enabled) {
      ui_trace_path = alloc_printf("%s/packet_trace.jsonl", out_dir);
      ui_trace_previous = alloc_printf("%s/packet_trace.previous.jsonl", out_dir);
    }
  }
  if (!ui_trace_enabled) return 0;
  if (ui_trace_file && ftell(ui_trace_file) >= UI_TRACE_FILE_LIMIT) {
    fclose(ui_trace_file);
    ui_trace_file = NULL;
    if (rename(ui_trace_path, ui_trace_previous)) { ui_trace_enabled = 0; return 0; }
  }
  if (!ui_trace_file) {
    int fd = open(ui_trace_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) { ui_trace_enabled = 0; return 0; }
    ui_trace_file = fdopen(fd, "a");
    if (!ui_trace_file) { close(fd); ui_trace_enabled = 0; return 0; }
    fseek(ui_trace_file, 0, SEEK_END);
  }
  return 1;
}

static void ui_trace_finish(void) {
  fputs("}\n", ui_trace_file);
  if (fflush(ui_trace_file) || ferror(ui_trace_file)) {
    fclose(ui_trace_file);
    ui_trace_file = NULL;
    ui_trace_enabled = 0;
  }
}

static u8 ui_trace_prefix(const char *kind) {
  if (!ui_trace_open()) return 0;
  fprintf(ui_trace_file, "{\"seq\":%llu,\"case_id\":%llu,\"timestamp_ms\":%llu,\"kind\":\"%s\"",
          (unsigned long long)++ui_trace_sequence, (unsigned long long)ui_trace_case,
          (unsigned long long)get_cur_time(), kind);
  return 1;
}

static void ui_trace_begin(void) {
  ui_trace_case = total_execs + 1;
  ui_trace_connection_failed = 0;
  if (!ui_trace_prefix("case_begin")) return;
  fputs(",\"seed_id\":", ui_trace_file);
  if (queue_cur) fprintf(ui_trace_file, "%u", queue_cur->index);
  else fputs("null", ui_trace_file);
  fprintf(ui_trace_file, ",\"target_state\":%u,\"stage\":", target_state_id);
  ui_trace_string(stage_name);
  ui_trace_finish();
}

static void ui_trace_message(const char *kind, const u8 *data, u32 length, u32 message_index, const char *result) {
  if (!ui_trace_prefix(kind)) return;
  u32 preview = length < UI_TRACE_PREVIEW ? length : UI_TRACE_PREVIEW;
  fprintf(ui_trace_file, ",\"message_index\":%u,\"length\":%u,\"truncated\":%s,\"data_hex\":\"",
          message_index, length, length > preview ? "true" : "false");
  for (u32 i = 0; i < preview && data; i++) fprintf(ui_trace_file, "%02x", data[i]);
  fprintf(ui_trace_file, "\",\"result\":\"%s\"", result);
  ui_trace_finish();
}

static void ui_trace_received(u32 before, u32 message_index) {
  if (response_buf_size > before)
    ui_trace_message("receive", (u8 *)response_buf + before, response_buf_size - before, message_index, "received");
}

static void ui_trace_end(int status, u64 elapsed_ms, u32 bitmap_head) {
  if (!ui_trace_prefix("case_end")) return;
  const char *result = response_buf_size ? "ok" : "no_response";
  u32 signal_number = 0;
  if (ui_trace_connection_failed) result = "connection_failed";
  if (stop_soon) result = "stopped";
  else if (WIFSIGNALED(status)) {
    signal_number = WTERMSIG(status);
    if (child_timed_out && signal_number == SIGKILL) result = "timeout";
    else if (signal_number != SIGTERM) result = "crash";
  } else if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) result = "crash";
  else if ((dumb_mode == 1 || no_forkserver) && bitmap_head == EXEC_FAIL_SIG) result = "execution_error";
  else if (WIFEXITED(status) && WEXITSTATUS(status)) result = "target_exit";
  fprintf(ui_trace_file, ",\"result\":\"%s\",\"signal\":%u,\"elapsed_ms\":%llu,\"response_bytes\":%u,\"states\":[",
          result, signal_number, (unsigned long long)elapsed_ms, response_buf_size);
  for (u32 i = 0; state_sequence && i < state_count && i < 64; i++)
    fprintf(ui_trace_file, "%s%u", i ? "," : "", state_sequence[i]);
  fputc(']', ui_trace_file);
  ui_trace_finish();
}
#endif
