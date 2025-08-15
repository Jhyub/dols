const std = @import("std");

const c = @cImport(
    {
        @cInclude("libcryptsetup.h");
    }
);

