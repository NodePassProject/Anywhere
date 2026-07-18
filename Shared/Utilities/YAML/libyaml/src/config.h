/*
 * Minimal hand-written config.h for the vendored libyaml (0.2.5).
 *
 * libyaml only consumes the YAML_VERSION_* macros from config.h — verified that
 * no HAVE_*_H feature macros are referenced anywhere under src/. This file is
 * kept beside the sources so libyaml's quote-include `#include "config.h"`
 * resolves here via same-directory lookup, and never collides with ngtcp2's
 * angle-include `#include <config.h>` (which resolves from the header search
 * paths instead). For that isolation to hold, this directory must NOT be added
 * to HEADER_SEARCH_PATHS.
 */
#ifndef ANYWHERE_LIBYAML_CONFIG_H
#define ANYWHERE_LIBYAML_CONFIG_H

#define YAML_VERSION_MAJOR 0
#define YAML_VERSION_MINOR 2
#define YAML_VERSION_PATCH 5
#define YAML_VERSION_STRING "0.2.5"

#endif /* ANYWHERE_LIBYAML_CONFIG_H */
