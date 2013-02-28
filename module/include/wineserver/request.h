/*
 * reguest.h
 *
 * Copyright (C) 2006  Insigma Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * project (http://www.longene.org) in the Insigma Research Institute,  
 * which is a subdivision of Insigma Co., Ltd (http://www.insigma.com.cn).
 * 
 * The project is sponsored by Insigma Co., Ltd.
 *
 * The authors can be reached at linux@insigma.com.cn.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of  the GNU General  Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Revision History:
 *   Dec 2008 - Created.
 */

/* 
 * request.h:
 * Refered to Wine code
 */

#ifndef _WINESERVER_REQUEST_H
#define _WINESERVER_REQUEST_H

#include "server.h"

#ifdef CONFIG_UNIFIED_KERNEL
/* max request length */
#define MAX_REQUEST_LENGTH  8192

/* request handler definition */
#define DECL_HANDLER(name) \
	void req_##name(const struct name##_request *req, struct name##_reply *reply)


/* Everything below this line is generated automatically by tools/make_requests */
/* ### make_requests begin ### */

DECL_HANDLER(new_process);
DECL_HANDLER(get_new_process_info);
DECL_HANDLER(new_thread);
DECL_HANDLER(get_startup_info);
DECL_HANDLER(init_process_done);
DECL_HANDLER(init_thread);
DECL_HANDLER(load_dll);
DECL_HANDLER(unload_dll);
DECL_HANDLER(queue_apc);
DECL_HANDLER(get_apc_result);
DECL_HANDLER(create_file);
DECL_HANDLER(open_file_object);
DECL_HANDLER(alloc_file_handle);
DECL_HANDLER(get_handle_fd);
DECL_HANDLER(flush_file);
DECL_HANDLER(lock_file);
DECL_HANDLER(unlock_file);
DECL_HANDLER(create_socket);
DECL_HANDLER(accept_socket);
DECL_HANDLER(register_accept_async);
DECL_HANDLER(set_socket_event);
DECL_HANDLER(get_socket_event);
DECL_HANDLER(enable_socket_event);
DECL_HANDLER(set_socket_deferred);
DECL_HANDLER(alloc_console);
DECL_HANDLER(free_console);
DECL_HANDLER(get_console_renderer_events);
DECL_HANDLER(open_console);
DECL_HANDLER(get_console_wait_event);
DECL_HANDLER(get_console_mode);
DECL_HANDLER(set_console_mode);
DECL_HANDLER(set_console_input_info);
DECL_HANDLER(get_console_input_info);
DECL_HANDLER(append_console_input_history);
DECL_HANDLER(get_console_input_history);
DECL_HANDLER(create_console_output);
DECL_HANDLER(set_console_output_info);
DECL_HANDLER(get_console_output_info);
DECL_HANDLER(write_console_input);
DECL_HANDLER(read_console_input);
DECL_HANDLER(write_console_output);
DECL_HANDLER(fill_console_output);
DECL_HANDLER(read_console_output);
DECL_HANDLER(move_console_output);
DECL_HANDLER(send_console_signal);
DECL_HANDLER(read_directory_changes);
DECL_HANDLER(read_change);
DECL_HANDLER(create_mapping);
DECL_HANDLER(open_mapping);
DECL_HANDLER(get_mapping_info);
DECL_HANDLER(create_snapshot);
DECL_HANDLER(next_process);
DECL_HANDLER(next_thread);
DECL_HANDLER(next_module);
DECL_HANDLER(wait_debug_event);
DECL_HANDLER(queue_exception_event);
DECL_HANDLER(get_exception_status);
DECL_HANDLER(output_debug_string);
DECL_HANDLER(continue_debug_event);
DECL_HANDLER(debug_process);
DECL_HANDLER(debug_break);
DECL_HANDLER(set_debugger_kill_on_exit);
DECL_HANDLER(create_key);
DECL_HANDLER(open_key);
DECL_HANDLER(delete_key);
DECL_HANDLER(flush_key);
DECL_HANDLER(enum_key);
DECL_HANDLER(set_key_value);
DECL_HANDLER(get_key_value);
DECL_HANDLER(enum_key_value);
DECL_HANDLER(delete_key_value);
DECL_HANDLER(load_registry);
DECL_HANDLER(unload_registry);
DECL_HANDLER(save_registry);
DECL_HANDLER(set_registry_notification);
DECL_HANDLER(create_timer);
DECL_HANDLER(open_timer);
DECL_HANDLER(set_timer);
DECL_HANDLER(cancel_timer);
DECL_HANDLER(get_timer_info);
DECL_HANDLER(get_thread_context);
DECL_HANDLER(set_thread_context);
DECL_HANDLER(add_atom);
DECL_HANDLER(delete_atom);
DECL_HANDLER(find_atom);
DECL_HANDLER(get_atom_information);
DECL_HANDLER(set_atom_information);
DECL_HANDLER(empty_atom_table);
DECL_HANDLER(init_atom_table);
DECL_HANDLER(get_msg_queue);
DECL_HANDLER(set_queue_fd);
DECL_HANDLER(set_queue_mask);
DECL_HANDLER(get_queue_status);
DECL_HANDLER(get_process_idle_event);
DECL_HANDLER(send_message);
DECL_HANDLER(post_quit_message);
DECL_HANDLER(send_hardware_message);
DECL_HANDLER(get_message);
DECL_HANDLER(reply_message);
DECL_HANDLER(accept_hardware_message);
DECL_HANDLER(get_message_reply);
DECL_HANDLER(set_win_timer);
DECL_HANDLER(kill_win_timer);
DECL_HANDLER(is_window_hung);
DECL_HANDLER(get_serial_info);
DECL_HANDLER(set_serial_info);
DECL_HANDLER(register_async);
DECL_HANDLER(cancel_async);
DECL_HANDLER(ioctl);
DECL_HANDLER(get_ioctl_result);
DECL_HANDLER(create_named_pipe);
DECL_HANDLER(get_named_pipe_info);
DECL_HANDLER(create_window);
DECL_HANDLER(destroy_window);
DECL_HANDLER(get_desktop_window);
DECL_HANDLER(set_window_owner);
DECL_HANDLER(get_window_info);
DECL_HANDLER(set_window_info);
DECL_HANDLER(set_parent);
DECL_HANDLER(get_window_parents);
DECL_HANDLER(get_window_children);
DECL_HANDLER(get_window_children_from_point);
DECL_HANDLER(get_window_tree);
DECL_HANDLER(set_window_pos);
DECL_HANDLER(set_window_visible_rect);
DECL_HANDLER(get_window_rectangles);
DECL_HANDLER(get_window_text);
DECL_HANDLER(set_window_text);
DECL_HANDLER(get_windows_offset);
DECL_HANDLER(get_visible_region);
DECL_HANDLER(get_window_region);
DECL_HANDLER(set_window_region);
DECL_HANDLER(get_update_region);
DECL_HANDLER(update_window_zorder);
DECL_HANDLER(redraw_window);
DECL_HANDLER(set_window_property);
DECL_HANDLER(remove_window_property);
DECL_HANDLER(get_window_property);
DECL_HANDLER(get_window_properties);
DECL_HANDLER(create_winstation);
DECL_HANDLER(open_winstation);
DECL_HANDLER(close_winstation);
DECL_HANDLER(get_process_winstation);
DECL_HANDLER(set_process_winstation);
DECL_HANDLER(enum_winstation);
DECL_HANDLER(create_desktop);
DECL_HANDLER(open_desktop);
DECL_HANDLER(close_desktop);
DECL_HANDLER(get_thread_desktop);
DECL_HANDLER(set_thread_desktop);
DECL_HANDLER(enum_desktop);
DECL_HANDLER(set_user_object_info);
DECL_HANDLER(attach_thread_input);
DECL_HANDLER(get_thread_input);
DECL_HANDLER(get_last_input_time);
DECL_HANDLER(get_key_state);
DECL_HANDLER(set_key_state);
DECL_HANDLER(set_foreground_window);
DECL_HANDLER(set_focus_window);
DECL_HANDLER(set_active_window);
DECL_HANDLER(set_capture_window);
DECL_HANDLER(set_caret_window);
DECL_HANDLER(set_caret_info);
DECL_HANDLER(set_hook);
DECL_HANDLER(remove_hook);
DECL_HANDLER(start_hook_chain);
DECL_HANDLER(finish_hook_chain);
DECL_HANDLER(get_hook_info);
DECL_HANDLER(create_class);
DECL_HANDLER(destroy_class);
DECL_HANDLER(set_class_info);
DECL_HANDLER(set_clipboard_info);
DECL_HANDLER(open_token);
DECL_HANDLER(set_global_windows);
DECL_HANDLER(adjust_token_privileges);
DECL_HANDLER(get_token_privileges);
DECL_HANDLER(check_token_privileges);
DECL_HANDLER(duplicate_token);
DECL_HANDLER(access_check);
DECL_HANDLER(get_token_user);
DECL_HANDLER(get_token_groups);
DECL_HANDLER(set_security_object);
DECL_HANDLER(get_security_object);
DECL_HANDLER(create_mailslot);
DECL_HANDLER(set_mailslot_info);
DECL_HANDLER(create_directory);
DECL_HANDLER(open_directory);
DECL_HANDLER(get_directory_entry);
DECL_HANDLER(create_symlink);
DECL_HANDLER(open_symlink);
DECL_HANDLER(query_symlink);
DECL_HANDLER(get_token_impersonation_level);
DECL_HANDLER(allocate_locally_unique_id);
DECL_HANDLER(create_device_manager);
DECL_HANDLER(create_device);
DECL_HANDLER(delete_device);
DECL_HANDLER(get_next_device_request);
DECL_HANDLER(make_process_system);
DECL_HANDLER(get_token_statistics);
DECL_HANDLER(create_completion);
DECL_HANDLER(open_completion);
DECL_HANDLER(add_completion);
DECL_HANDLER(remove_completion);
DECL_HANDLER(query_completion);
DECL_HANDLER(set_completion_info);
DECL_HANDLER(add_fd_completion);
DECL_HANDLER(get_window_layered_info);
DECL_HANDLER(set_window_layered_info);
DECL_HANDLER(async_set_result);

typedef void (*req_handler)(const void *req, void *reply);
static const req_handler req_handlers[REQ_NB_REQUESTS] =
{
	(req_handler)req_new_process,
	(req_handler)req_get_new_process_info,
	(req_handler)req_new_thread,
	(req_handler)req_get_startup_info,
	(req_handler)req_init_process_done,
	(req_handler)req_init_thread,
	(req_handler)NULL, /* req_terminate_process */
	(req_handler)NULL, /* req_terminate_thread */
	(req_handler)NULL, /* req_get_process_info */
	(req_handler)NULL, /* req_set_process_info */
	(req_handler)NULL, /* req_get_thread_info */
	(req_handler)NULL, /* req_set_thread_info */
	(req_handler)NULL, /* req_get_dll_info */
	(req_handler)NULL, /* req_suspend_thread */
	(req_handler)NULL, /* req_resume_thread */
	(req_handler)req_load_dll,
	(req_handler)req_unload_dll,
	(req_handler)req_queue_apc,
	(req_handler)req_get_apc_result,
	(req_handler)NULL, /* req_close_handle */
	(req_handler)NULL, /* req_set_handle_info */
	(req_handler)NULL, /* req_dup_handle */
	(req_handler)NULL, /* req_open_process */
	(req_handler)NULL, /* req_open_thread */
	(req_handler)NULL, /* req_select */
	(req_handler)NULL, /* req_create_event */
	(req_handler)NULL, /* req_event_op */
	(req_handler)NULL, /* req_open_event */
	(req_handler)NULL, /* req_create_mutex */
	(req_handler)NULL, /* req_release_mutex */
	(req_handler)NULL, /* req_open_mutex */
	(req_handler)NULL, /* req_create_semaphore */
	(req_handler)NULL, /* req_release_semaphore */
	(req_handler)NULL, /* req_open_semaphore */
	(req_handler)req_create_file,
	(req_handler)req_open_file_object,
	(req_handler)req_alloc_file_handle,
	(req_handler)req_get_handle_fd,
	(req_handler)req_flush_file,
	(req_handler)req_lock_file,
	(req_handler)req_unlock_file,
	(req_handler)req_create_socket,
	(req_handler)req_accept_socket,
	(req_handler)req_register_accept_async,
	(req_handler)req_set_socket_event,
	(req_handler)req_get_socket_event,
	(req_handler)req_enable_socket_event,
	(req_handler)req_set_socket_deferred,
	(req_handler)req_alloc_console,
	(req_handler)req_free_console,
	(req_handler)req_get_console_renderer_events,
	(req_handler)req_open_console,
	(req_handler)req_get_console_wait_event,
	(req_handler)req_get_console_mode,
	(req_handler)req_set_console_mode,
	(req_handler)req_set_console_input_info,
	(req_handler)req_get_console_input_info,
	(req_handler)req_append_console_input_history,
	(req_handler)req_get_console_input_history,
	(req_handler)req_create_console_output,
	(req_handler)req_set_console_output_info,
	(req_handler)req_get_console_output_info,
	(req_handler)req_write_console_input,
	(req_handler)req_read_console_input,
	(req_handler)req_write_console_output,
	(req_handler)req_fill_console_output,
	(req_handler)req_read_console_output,
	(req_handler)req_move_console_output,
	(req_handler)req_send_console_signal,
	(req_handler)req_read_directory_changes,
	(req_handler)req_read_change,
	(req_handler)req_create_mapping,
	(req_handler)req_open_mapping,
	(req_handler)req_get_mapping_info,
	(req_handler)req_create_snapshot,
	(req_handler)req_next_process,
	(req_handler)req_next_thread,
	(req_handler)req_next_module,
	(req_handler)req_wait_debug_event,
	(req_handler)req_queue_exception_event,
	(req_handler)req_get_exception_status,
	(req_handler)req_output_debug_string,
	(req_handler)req_continue_debug_event,
	(req_handler)req_debug_process,
	(req_handler)req_debug_break,
	(req_handler)req_set_debugger_kill_on_exit,
	(req_handler)NULL, /* req_read_process_memory */
	(req_handler)NULL, /* req_write_process_memory */
	(req_handler)req_create_key,
	(req_handler)req_open_key,
	(req_handler)req_delete_key,
	(req_handler)req_flush_key,
	(req_handler)req_enum_key,
	(req_handler)req_set_key_value,
	(req_handler)req_get_key_value,
	(req_handler)req_enum_key_value,
	(req_handler)req_delete_key_value,
	(req_handler)req_load_registry,
	(req_handler)req_unload_registry,
	(req_handler)req_save_registry,
	(req_handler)req_set_registry_notification,
	(req_handler)req_create_timer,
	(req_handler)req_open_timer,
	(req_handler)req_set_timer,
	(req_handler)req_cancel_timer,
	(req_handler)req_get_timer_info,
	(req_handler)req_get_thread_context,
	(req_handler)req_set_thread_context,
	(req_handler)NULL, /* req_get_selector_entry */
	(req_handler)req_add_atom,
	(req_handler)req_delete_atom,
	(req_handler)req_find_atom,
	(req_handler)req_get_atom_information,
	(req_handler)req_set_atom_information,
	(req_handler)req_empty_atom_table,
	(req_handler)req_init_atom_table,
	(req_handler)req_get_msg_queue,
	(req_handler)req_set_queue_fd,
	(req_handler)req_set_queue_mask,
	(req_handler)req_get_queue_status,
	(req_handler)req_get_process_idle_event,
	(req_handler)req_send_message,
	(req_handler)req_post_quit_message,
	(req_handler)req_send_hardware_message,
	(req_handler)req_get_message,
	(req_handler)req_reply_message,
	(req_handler)req_accept_hardware_message,
	(req_handler)req_get_message_reply,
	(req_handler)req_set_win_timer,
	(req_handler)req_kill_win_timer,
	(req_handler)req_is_window_hung,
	(req_handler)req_get_serial_info,
	(req_handler)req_set_serial_info,
	(req_handler)req_register_async,
	(req_handler)req_cancel_async,
	(req_handler)req_ioctl,
	(req_handler)req_get_ioctl_result,
	(req_handler)req_create_named_pipe,
	(req_handler)req_get_named_pipe_info,
	(req_handler)req_create_window,
	(req_handler)req_destroy_window,
	(req_handler)req_get_desktop_window,
	(req_handler)req_set_window_owner,
	(req_handler)req_get_window_info,
	(req_handler)req_set_window_info,
	(req_handler)req_set_parent,
	(req_handler)req_get_window_parents,
	(req_handler)req_get_window_children,
	(req_handler)req_get_window_children_from_point,
	(req_handler)req_get_window_tree,
	(req_handler)req_set_window_pos,
	(req_handler)req_set_window_visible_rect,
	(req_handler)req_get_window_rectangles,
	(req_handler)req_get_window_text,
	(req_handler)req_set_window_text,
	(req_handler)req_get_windows_offset,
	(req_handler)req_get_visible_region,
	(req_handler)req_get_window_region,
	(req_handler)req_set_window_region,
	(req_handler)req_get_update_region,
	(req_handler)req_update_window_zorder,
	(req_handler)req_redraw_window,
	(req_handler)req_set_window_property,
	(req_handler)req_remove_window_property,
	(req_handler)req_get_window_property,
	(req_handler)req_get_window_properties,
	(req_handler)req_create_winstation,
	(req_handler)req_open_winstation,
	(req_handler)req_close_winstation,
	(req_handler)req_get_process_winstation,
	(req_handler)req_set_process_winstation,
	(req_handler)req_enum_winstation,
	(req_handler)req_create_desktop,
	(req_handler)req_open_desktop,
	(req_handler)req_close_desktop,
	(req_handler)req_get_thread_desktop,
	(req_handler)req_set_thread_desktop,
	(req_handler)req_enum_desktop,
	(req_handler)req_set_user_object_info,
	(req_handler)req_attach_thread_input,
	(req_handler)req_get_thread_input,
	(req_handler)req_get_last_input_time,
	(req_handler)req_get_key_state,
	(req_handler)req_set_key_state,
	(req_handler)req_set_foreground_window,
	(req_handler)req_set_focus_window,
	(req_handler)req_set_active_window,
	(req_handler)req_set_capture_window,
	(req_handler)req_set_caret_window,
	(req_handler)req_set_caret_info,
	(req_handler)req_set_hook,
	(req_handler)req_remove_hook,
	(req_handler)req_start_hook_chain,
	(req_handler)req_finish_hook_chain,
	(req_handler)req_get_hook_info,
	(req_handler)req_create_class,
	(req_handler)req_destroy_class,
	(req_handler)req_set_class_info,
	(req_handler)req_set_clipboard_info,
	(req_handler)req_open_token,
	(req_handler)req_set_global_windows,
	(req_handler)req_adjust_token_privileges,
	(req_handler)req_get_token_privileges,
	(req_handler)req_check_token_privileges,
	(req_handler)req_duplicate_token,
	(req_handler)req_access_check,
	(req_handler)req_get_token_user,
	(req_handler)req_get_token_groups,
	(req_handler)req_set_security_object,
	(req_handler)req_get_security_object,
	(req_handler)req_create_mailslot,
	(req_handler)req_set_mailslot_info,
	(req_handler)req_create_directory,
	(req_handler)req_open_directory,
	(req_handler)req_get_directory_entry,
	(req_handler)req_create_symlink,
	(req_handler)req_open_symlink,
	(req_handler)req_query_symlink,
	(req_handler)NULL, /* req_get_object_info */
	(req_handler)req_get_token_impersonation_level,
	(req_handler)req_allocate_locally_unique_id,
	(req_handler)req_create_device_manager,
	(req_handler)req_create_device,
	(req_handler)req_delete_device,
	(req_handler)req_get_next_device_request,
	(req_handler)req_make_process_system,
	(req_handler)req_get_token_statistics,
	(req_handler)req_create_completion,
	(req_handler)req_open_completion,
	(req_handler)req_add_completion,
	(req_handler)req_remove_completion,
	(req_handler)req_query_completion,
	(req_handler)req_set_completion_info,
	(req_handler)req_add_fd_completion,
	(req_handler)req_get_window_layered_info,
	(req_handler)req_set_window_layered_info,
	(req_handler)req_async_set_result,
};

#endif  /* CONFIG_UNIFIED_KERNEL */
#endif  /* _WINESERVER_REQUEST_H */


