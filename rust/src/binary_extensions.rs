//! Copied from `ggshield/utils/_binary_extensions.py`, which decides which files
//! are read from disk and scanned. CI fails if the two lists drift.

pub const BINARY_EXTENSIONS: [&str; 208] = [
    "3g2", "3gp", "7z", "8svx", "a", "aa", "aac", "aax", "ace", "act", "adf", "afa", "aiff", "aml",
    "amr", "amv", "ape", "apk", "ar", "arc", "arj", "au", "avi", "awv", "b1", "b6z", "ba", "bh",
    "bin", "bmp", "bz2", "cab", "car", "cfs", "cpio", "cpt", "dar", "db", "dct", "dd", "dgc",
    "dll", "dmg", "drc", "dss", "dvf", "ear", "ecc", "efi", "exe", "f", "f4a", "f4b", "f4p", "f4v",
    "flac", "flv", "fpx", "gca", "gif", "gifv", "gsm", "gz", "ha", "hki", "ice", "icns", "ico",
    "ide", "iklax", "iso", "ivs", "j2c", "j2k", "jar", "jfif", "jif", "jp2", "jpeg", "jpg", "jpx",
    "kgb", "lbr", "lha", "lz", "lzh", "lzma", "lzo", "lzx", "m2ts", "m4a", "m4b", "m4p", "m4v",
    "mar", "mkv", "mmdb", "mmf", "mng", "mo", "mogg", "mov", "mp2", "mp3", "mp4", "mpc", "mpe",
    "mpeg", "mpg", "mpv", "msv", "mts", "mxf", "nsf", "nsv", "o", "oga", "ogg", "ogv", "opus",
    "pak", "paq6", "paq7", "paq8", "par", "par2", "partimg", "pcd", "pdf", "pea", "pim", "pit",
    "png", "pyc", "qda", "qt", "ra", "rar", "raw", "rev", "rk", "rm", "rmvb", "roq", "rz", "s7z",
    "sbx", "sda", "sea", "sen", "ser", "sfark", "sfx", "shar", "shk", "sit", "sitx", "sldasm",
    "slddrt", "slddrw", "sldprt", "sln", "sqlite", "sqx", "suo", "svg", "svi", "sz", "tar", "tbz2",
    "tgz", "tif", "tiff", "tlz", "tta", "twbw", "txz", "uc", "uc0", "uc1", "uc2", "uca", "ucn",
    "ue2", "uha", "ur2", "vob", "vox", "war", "wav", "webm", "wim", "wmv", "wv", "xar", "xcf",
    "xls", "xlsx", "xp3", "xz", "yuv", "yz1", "z", "zip", "zipx", "zoo", "zpaq", "zz",
];
