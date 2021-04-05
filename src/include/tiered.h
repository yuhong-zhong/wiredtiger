/*-
 * Copyright (c) 2014-present MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

/*
 * WT_TIERED_MANAGER --
 *	A structure that holds resources used to manage any tiered storage
 *	for the whole database.
 */
struct __wt_tiered_manager {
    uint64_t wait_usecs; /* Wait time period */
    uint32_t workers;    /* Current number of workers */
    uint32_t workers_max;
    uint32_t workers_min;

#define WT_TIERED_MAX_WORKERS 20
#define WT_TIERED_MIN_WORKERS 1

/* AUTOMATIC FLAG VALUE GENERATION START */
#define WT_TIERED_MANAGER_SHUTDOWN 0x1u /* Manager has shut down */
                                        /* AUTOMATIC FLAG VALUE GENERATION STOP */
    uint32_t flags;
};

/*
 * WT_CURSOR_TIERED --
 *	An tiered cursor.
 */
struct __wt_cursor_tiered {
    WT_CURSOR iface;

    WT_TIERED *tiered;

    WT_CURSOR **cursors;
    WT_CURSOR *current; /* The current cursor for iteration */
    WT_CURSOR *primary; /* The current primary */

/* AUTOMATIC FLAG VALUE GENERATION START */
#define WT_CURTIERED_ACTIVE 0x1u       /* Incremented the session count */
#define WT_CURTIERED_ITERATE_NEXT 0x2u /* Forward iteration */
#define WT_CURTIERED_ITERATE_PREV 0x4u /* Backward iteration */
#define WT_CURTIERED_MULTIPLE 0x8u     /* Multiple cursors have values */
                                       /* AUTOMATIC FLAG VALUE GENERATION STOP */
    uint32_t flags;
};

/*
 * WT_TIERED --
 *	Handle for a tiered data source. This data structure is used as the basis for metadata
 *	as the top level definition of a tiered table. This structure tells us where to find the
 *	parts of the tree and in what order we should look at the tiers. Prior to the first call
 *	to flush_tier the only tier that exists will be the local disk represented by a file: URI.
 *	Then a second (or more) set of tiers will be where the tiered data lives. The non-local
 *	tier will point to a tier: URI and that is described by a WT_TIERED_TREE data structure
 *	that will encapsulate what the current state of the individual objects is.
 */
struct __wt_tiered {
    WT_DATA_HANDLE iface;

    const char *name;   /* Name of table */
    const char *config; /* Config to use for each object */
    const char *key_format, *value_format;

    WT_DATA_HANDLE **tiers; /* Tiers array */
    u_int ntiers;

    uint64_t object_num; /* Global next object number */

    WT_COLLATOR *collator; /* TODO: handle custom collation */
    /* TODO: What about compression, encryption, etc? Do we need to worry about that here? */

/* AUTOMATIC FLAG VALUE GENERATION START */
#define WT_TIERED_LOCAL 0x1u
#define WT_TIERED_SHARED 0x2u
    /* AUTOMATIC FLAG VALUE GENERATION STOP */
    uint32_t flags;
};

/*
 * WT_TIERED_OBJECT --
 *     Definition of a tiered object. This is a single object in a tiered tree.
 *     This is the lowest level data structure and item that makes
 *     up a tiered table. This structure contains the information needed to construct the name of
 *     this object and how to access it.
 */
struct __wt_tiered_ojbect {
    const char *uri;      /* Data source for this object */
    WT_TIERED_TREE *tree; /* Pointer to tree this object is part of */
    uint64_t count;       /* Approximate count of records */
    uint64_t size;        /* Final size of object */
    uint64_t switch_txn;  /* Largest txn that can write to this object */
    uint64_t switch_ts;   /* Timestamp for switching */
    uint32_t id;          /* This object's id */
    uint32_t generation;  /* Do we need this?? */
    uint32_t refcnt;      /* Number of references */

/* AUTOMATIC FLAG VALUE GENERATION START */
#define WT_TIERED_OBJ_LOCAL 0x1u /* Local resident also */
    /* AUTOMATIC FLAG VALUE GENERATION STOP */
    uint32_t flags;
};

/*
 * WT_TIERED_TREE --
 *     Definition of the shared tiered portion of a tree. This contains the list of individual
 *     objects that exist in this tree and how to access them.
 */
struct __wt_tiered_tree {
    const char *name, *config;
    const char *key_format, *value_format;
    const char *file_config;

/* AUTOMATIC FLAG VALUE GENERATION START */
#define WT_TIERED_TREE_UNUSED 0x1u
    /* AUTOMATIC FLAG VALUE GENERATION STOP */
    uint32_t flags;
};
