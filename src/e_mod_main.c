#define EFL_BETA_API_SUPPORT
#define EFL_EO_API_SUPPORT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>

#include <e.h>
#include <Eina.h>
#include <Ecore.h>
#include <Ecore_Con.h>

#include "e_mod_main.h"

#define _EET_ENTRY "config"

typedef struct
{
   E_Gadcon_Client *gcc;
   Evas_Object *o_icon;
   Ecore_Event_Handler *exe_data_hdl;
   Ecore_Event_Handler *exe_error_hdl;
   Ecore_Event_Handler *exe_del_hdl;

   Eina_Stringshare *passwd;
   Ecore_Exe *gui_cmd_exe;
   Ecore_Exe *script_cmd_exe;
   Eina_List *mount_exes;

   unsigned int notif_id;
} Instance;

#define PRINT _printf

typedef struct
{
   Eina_Stringshare *enc_dir;
   Eina_Stringshare *mount_point;
} Dir_Info;

typedef struct
{
   Eina_Stringshare *script_cmd;
   Eina_Stringshare *gui_cmd;
   Eina_List *directories; /* List of Dir_Info */
} Config;

typedef struct
{
   Eina_List **pList;
   void *data;
} List_Remove_Timer_Data;

static E_Module *_module = NULL;
static Config *_config = NULL;
static Eet_Data_Descriptor *_config_edd = NULL;

static Eina_Bool
_data_remove_from_list(void *data)
{
   List_Remove_Timer_Data *td = data;
   *td->pList = eina_list_remove(*td->pList, td->data);
   free(td);
   return ECORE_CALLBACK_CANCEL;
}

static int
_printf(const char *fmt, ...)
{
   static FILE *fp = NULL;
   char printf_buf[1024];
   va_list args;
   int printed;

   if (!fp)
     {
        char path[1024];
        sprintf(path, "%s/e_decrypt/log", efreet_config_home_get());
        fp = fopen(path, "a");
     }

   va_start(args, fmt);
   printed = vsprintf(printf_buf, fmt, args);
   va_end(args);

   fwrite(printf_buf, 1, strlen(printf_buf), fp);
   fflush(fp);

   return printed;
}

static void
_config_eet_load()
{
   Eet_Data_Descriptor *dir_edd;
   if (_config_edd) return;
   Eet_Data_Descriptor_Class eddc;

   EET_EINA_STREAM_DATA_DESCRIPTOR_CLASS_SET(&eddc, Dir_Info);
   dir_edd = eet_data_descriptor_stream_new(&eddc);
   EET_DATA_DESCRIPTOR_ADD_BASIC(dir_edd, Dir_Info, "enc_dir", enc_dir, EET_T_STRING);
   EET_DATA_DESCRIPTOR_ADD_BASIC(dir_edd, Dir_Info, "mount_point", mount_point, EET_T_STRING);

   EET_EINA_STREAM_DATA_DESCRIPTOR_CLASS_SET(&eddc, Config);
   _config_edd = eet_data_descriptor_stream_new(&eddc);
   EET_DATA_DESCRIPTOR_ADD_BASIC(_config_edd, Config, "script_cmd", script_cmd, EET_T_STRING);
   EET_DATA_DESCRIPTOR_ADD_BASIC(_config_edd, Config, "gui_cmd", gui_cmd, EET_T_STRING);
   EET_DATA_DESCRIPTOR_ADD_LIST(_config_edd, Config, "directories", directories, dir_edd);
}

static void
_config_save()
{
   char path[1024];
   sprintf(path, "%s/e_decrypt/config", efreet_config_home_get());
   _config_eet_load();
   Eet_File *file = eet_open(path, EET_FILE_MODE_WRITE);
   eet_data_write(file, _config_edd, _EET_ENTRY, _config, EINA_TRUE);
   eet_close(file);
}

static Eina_Bool
_mkdir(const char *dir)
{
   if (!ecore_file_exists(dir))
     {
        Eina_Bool success = ecore_file_mkdir(dir);
        if (!success)
          {
             PRINT("Cannot create a config folder \"%s\"\n", dir);
             return EINA_FALSE;
          }
     }
   return EINA_TRUE;
}

static void
_config_init()
{
   char path[1024];
   Dir_Info *dir;

   sprintf(path, "%s/e_decrypt", efreet_config_home_get());
   if (!_mkdir(path)) return;

   _config_eet_load();
   sprintf(path, "%s/e_decrypt/config", efreet_config_home_get());
   Eet_File *file = eet_open(path, EET_FILE_MODE_READ);
   if (!file)
     {
        PRINT("New config\n");
        dir = calloc(1, sizeof(*dir));

        dir->enc_dir = eina_stringshare_add("example_enc_dir");
        dir->mount_point = eina_stringshare_add("example_mount_point");

        _config = calloc(1, sizeof(Config));
        _config->script_cmd = NULL;
        _config->gui_cmd = eina_stringshare_add("zenity --password");
        _config->directories = eina_list_append(_config->directories, dir);
        _config_save();
     }
   else
     {
        _config = eet_data_read(file, _config_edd, _EET_ENTRY);
        eet_close(file);
     }
}

static void
_config_shutdown()
{
   Dir_Info *dir;
   EINA_LIST_FREE(_config->directories, dir)
     {
        eina_stringshare_del(dir->enc_dir);
        eina_stringshare_del(dir->mount_point);
        free(dir);
     }
   eina_stringshare_del(_config->script_cmd);
   eina_stringshare_del(_config->gui_cmd);
   free(_config);
   _config = NULL;
}

static Eina_Bool
_cmd_end_cb(void *data, int type EINA_UNUSED, void *event)
{
   Instance *inst = data;
   Ecore_Exe_Event_Del *event_info = (Ecore_Exe_Event_Del *)event;
   Ecore_Exe *exe = event_info->exe;
   if (!exe) return ECORE_CALLBACK_PASS_ON;
   if (exe == inst->gui_cmd_exe || exe == inst->script_cmd_exe)
     {
        Eina_List *itr;
        Dir_Info *dir;
        if (exe == inst->gui_cmd_exe) inst->gui_cmd_exe = NULL;
        if (exe == inst->script_cmd_exe) inst->script_cmd_exe = NULL;
        EINA_LIST_FOREACH(_config->directories, itr, dir)
          {
             char cmd[1024];
             sprintf(cmd, "encfs -S %s %s", dir->enc_dir, dir->mount_point);
             exe = ecore_exe_pipe_run(cmd,
                   ECORE_EXE_PIPE_READ | ECORE_EXE_PIPE_WRITE | ECORE_EXE_PIPE_ERROR, inst);
             ecore_exe_send(exe, inst->passwd, strlen(inst->passwd));
             inst->mount_exes = eina_list_append(inst->mount_exes, exe);
          }
        //e_gadcon_client_hide(inst->gcc);
     }

   List_Remove_Timer_Data *td = malloc(sizeof(*td));
   td->pList = &inst->mount_exes;
   td->data = exe;
   ecore_timer_add(2.0, _data_remove_from_list, td);

   return ECORE_CALLBACK_DONE;
}

static void
_notification_id_update(void *d, unsigned int id)
{
   Instance *inst = d;

   inst->notif_id = id;
}

static Eina_Bool
_cmd_output_cb(void *data, int type, void *event)
{
   E_Notification_Notify n;
   char buf_icon[1024];
   char output_buf[10024];
   Instance *inst = data;
   Ecore_Exe_Event_Data *event_data = (Ecore_Exe_Event_Data *)event;
   Ecore_Exe *exe = event_data->exe;

   /* Get password from script or GUI */
   if (type == ECORE_EXE_EVENT_DATA &&
         (exe == inst->gui_cmd_exe || exe == inst->script_cmd_exe))
     {
        eina_stringshare_del(inst->passwd);
        inst->passwd = eina_stringshare_add_length(event_data->data, event_data->size);
        PRINT("PASSWD %s\n", inst->passwd);
        return ECORE_CALLBACK_PASS_ON;
     }

   if (eina_list_data_find(inst->mount_exes, exe))
     {
        const char *begin = event_data->data;

        snprintf(buf_icon, sizeof(buf_icon), "%s/icon.png", e_module_dir_get(_module));
        PRINT(begin);

        if (type == ECORE_EXE_EVENT_ERROR)
           sprintf(output_buf, "<color=#F00>%*s</color>", event_data->size, begin);
        else
           sprintf(output_buf, "<color=#0F0>%*s</color>", event_data->size, begin);

        memset(&n, 0, sizeof(E_Notification_Notify));
        n.app_name = "e_decrypt";
        n.timeout = 3000;
        n.replaces_id = inst->notif_id;
        n.icon.icon_path = buf_icon;
        n.body = output_buf;
        n.urgency = E_NOTIFICATION_NOTIFY_URGENCY_CRITICAL;
        e_notification_client_send(&n, _notification_id_update, inst);
     }

   return ECORE_CALLBACK_DONE;
}

static Eo *
_icon_create(Eo *parent, const char *path, Eo **wref)
{
   Eo *ic = wref ? *wref : NULL;
   if (!ic)
     {
        ic = elm_icon_add(parent);
        elm_icon_standard_set(ic, path);
        evas_object_show(ic);
        if (wref) efl_wref_add(ic, wref);
     }
   return ic;
}

static Instance *
_instance_create()
{
   char path[1024];
   Instance *inst = calloc(1, sizeof(Instance));

   sprintf(path, "%s/e_decrypt", efreet_config_home_get());
   if (!_mkdir(path)) return NULL;
   sprintf(path, "%s/e_decrypt/config", efreet_config_home_get());

   return inst;
}

static void
_instance_delete(Instance *inst)
{
   ecore_event_handler_del(inst->exe_data_hdl);
   ecore_event_handler_del(inst->exe_error_hdl);
   ecore_event_handler_del(inst->exe_del_hdl);
   if (inst->o_icon) evas_object_del(inst->o_icon);

   free(inst);
}

static void
_button_cb_mouse_down(void *data, Evas *e EINA_UNUSED, Evas_Object *obj EINA_UNUSED, void *event_info)
{
   Instance *inst;
   Evas_Event_Mouse_Down *ev;

   inst = data;
   ev = event_info;

   if (ev->button == 1 && !inst->gui_cmd_exe)
     {
        inst->gui_cmd_exe = ecore_exe_pipe_run(_config->gui_cmd,
              ECORE_EXE_PIPE_READ | ECORE_EXE_PIPE_ERROR, inst);
        PRINT("GUI EXE BEGIN %p\n", inst->gui_cmd_exe);
     }
}

static E_Gadcon_Client *
_gc_init(E_Gadcon *gc, const char *name, const char *id, const char *style)
{
   Instance *inst;
   E_Gadcon_Client *gcc;
   char buf[4096];

   inst = _instance_create();
   _config_init();

   snprintf(buf, sizeof(buf), "%s/icon.png", e_module_dir_get(_module));

   inst->o_icon = _icon_create(gc->evas, buf, NULL);

   gcc = e_gadcon_client_new(gc, name, id, style, inst->o_icon);
   gcc->data = inst;
   inst->gcc = gcc;

   evas_object_event_callback_add(inst->o_icon, EVAS_CALLBACK_MOUSE_DOWN,
				  _button_cb_mouse_down, inst);

   inst->exe_data_hdl = ecore_event_handler_add(ECORE_EXE_EVENT_DATA, _cmd_output_cb, inst);
   inst->exe_error_hdl = ecore_event_handler_add(ECORE_EXE_EVENT_ERROR, _cmd_output_cb, inst);
   inst->exe_del_hdl = ecore_event_handler_add(ECORE_EXE_EVENT_DEL, _cmd_end_cb, inst);

   if (_config->script_cmd)
      inst->script_cmd_exe = ecore_exe_pipe_run(_config->script_cmd,
            ECORE_EXE_PIPE_READ | ECORE_EXE_PIPE_ERROR, inst);
   return gcc;
}

static void
_gc_shutdown(E_Gadcon_Client *gcc)
{
   _instance_delete(gcc->data);
   _config_shutdown();
}

static void
_gc_orient(E_Gadcon_Client *gcc, E_Gadcon_Orient orient EINA_UNUSED)
{
   e_gadcon_client_aspect_set(gcc, 32, 16);
   e_gadcon_client_min_size_set(gcc, 32, 16);
}

static const char *
_gc_label(const E_Gadcon_Client_Class *client_class EINA_UNUSED)
{
   return "e_decrypt";
}

static Evas_Object *
_gc_icon(const E_Gadcon_Client_Class *client_class EINA_UNUSED, Evas *evas)
{
   char buf[4096];

   if (!_module) return NULL;

   snprintf(buf, sizeof(buf), "%s/icon.png", e_module_dir_get(_module));

   return _icon_create(evas, buf, NULL);
}

static const char *
_gc_id_new(const E_Gadcon_Client_Class *client_class)
{
   char buf[32];
   static int id = 0;
   sprintf(buf, "%s.%d", client_class->name, ++id);
   return eina_stringshare_add(buf);
}

EAPI E_Module_Api e_modapi =
{
   E_MODULE_API_VERSION, "e_decrypt"
};

static const E_Gadcon_Client_Class _gc_class =
{
   GADCON_CLIENT_CLASS_VERSION, "e_decrypt",
   {
      _gc_init, _gc_shutdown, _gc_orient, _gc_label, _gc_icon, _gc_id_new, NULL, NULL
   },
   E_GADCON_CLIENT_STYLE_PLAIN
};

EAPI void *
e_modapi_init(E_Module *m)
{
   ecore_init();
   ecore_con_init();
   ecore_con_url_init();
   efreet_init();

   _module = m;
   e_gadcon_provider_register(&_gc_class);

   return m;
}

EAPI int
e_modapi_shutdown(E_Module *m EINA_UNUSED)
{
   e_gadcon_provider_unregister(&_gc_class);

   _module = NULL;
   efreet_shutdown();
   ecore_con_url_shutdown();
   ecore_con_shutdown();
   ecore_shutdown();
   return 1;
}

EAPI int
e_modapi_save(E_Module *m EINA_UNUSED)
{
   return 1;
}
