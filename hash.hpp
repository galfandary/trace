static inline uint32_t MMH3Rot(uint32_t x, int8_t r) {
    return (x << r) | (x >> (32 - r));
}

static inline uint32_t MMH3Mix1(uint32_t x) {
    return 0x1b873593 * MMH3Rot(0xcc9e2d51 * x, 15);
}

static inline uint32_t MMH3Mix2(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

static inline uint32_t MurmurHash3(const void *data, size_t len) {
    auto B = sizeof(uint32_t), N = len / B, R = len % B;
    auto p = (const uint32_t *) data, end = p + N;
    uint32_t h = 0;

    while (p < end) {
        h ^= MMH3Mix1(*p++);
        h = MMH3Rot(h, 13); 
        h = h * 5 + 0xe6546b64;
    }

    uint32_t k = 0;
    auto tail = (const uint8_t *) end;
    switch (R) {
    case 3: k ^= tail[2] << 16;
    case 2: k ^= tail[1] << 8;
    case 1: k ^= tail[0];
        h ^= MMH3Mix1(k);
    }

    h = MMH3Mix2(h ^ len);
    return h;
} 

static inline uint32_t MurmurHash3(const std::string &s) {
    return MurmurHash3(s.data(), s.size());
}

class MMH3Set_t {
    size_t size;
    size_t load;
    size_t grow;
    size_t allc;
    char **data;
    void alloc(size_t n) {
        data = (char **) calloc(allc = n, sizeof(char *));
    }
    void put(char *s, size_t l) {
        auto i = MurmurHash3(s, l) % allc;
        while (data[i]) i = (i + 1) % allc;
        data[i] = s;
    }
    void put(char *s) {
        if (s) put(s, strlen(s));
    }
    bool resize() {
        if (++size * 100 < allc * load) return false;
        auto n = allc;
        auto d = data;
        alloc(grow * allc / 100);
        for (size_t i = 0; i < n; i++)
            put(d[i]);
        free(d);
        return true;
    }
public:
    const char *add(const char *s, size_t l = 0, bool newOnly = true) {
        if (!s) return 0;
        if (!l) l = strlen(s);
        auto i = MurmurHash3(s, l) % allc;
        for (;;) {
            auto t = data[i];
            if (!t) break;
            if (!strcmp(s, t)) return newOnly ? 0 : t;
            i = (i + 1) % allc;
        }
        auto r = resize();
        auto d = strdup(s);
        if (r) put(d, l); else data[i] = d;
        return d;
    }
    MMH3Set_t(size_t n = 1024, size_t l = 25, size_t g = 400) {
        size = 0;
        load = l;
        grow = g;
        alloc(n);
    }
    ~MMH3Set_t() {
        for (size_t i = 0; i < allc; i++)
            if (data[i]) free(data[i]);
        free(data);
    }
};
