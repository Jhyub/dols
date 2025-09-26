const std = @import("std");

pub const IpConfigConfig = struct {
    interfaces: []const []const u8,
    timeout: ?u32,
};

pub const ConfigFile = struct {
    port: ?u16,
    auth_try_limit: ?u32,
    ip: ?IpConfigConfig,
};

pub const Config = struct {
    port: u16,
    auth_try_limit: u32,
    ip: ?IpConfigConfig,

    pub fn init(from: ConfigFile) Config {
        return Config{
            .port = from.port orelse 22,
            .auth_try_limit = from.auth_try_limit orelse 0,
            .ip = from.ip,
        };
    }
};
