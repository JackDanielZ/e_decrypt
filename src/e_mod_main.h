#ifndef E_MOD_MAIN_H
#define E_MOD_MAIN_H

#ifdef EAPI
#undef EAPI
#endif
#define EAPI __attribute__ ((visibility("default")))

#ifndef STAND_ALONE
EAPI extern E_Module_Api e_modapi;

EAPI void *e_modapi_init     (E_Module *m);
EAPI int   e_modapi_shutdown (E_Module *m);
EAPI int   e_modapi_save     (E_Module *m);
#endif

#endif
