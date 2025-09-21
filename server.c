#include "csapp.h"
#include "cJSON.h"
#include "sbuf.h"
#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum
{
    false = 0,
    true = 1
} bool;

struct Membuffer
{
    char *data;
    size_t size;
};

typedef enum
{
    ENTRY,
    REQ_DIR,
    REQ_FILE
} RequestedType_t;

typedef struct
{
    char package[128];
    char version[64];
    char path[512];
    RequestedType_t type;
} ParsedUri_t;

sbuf_t sbuf;
char *registry;
#define SBUF_SIZE 16
#define WORKER_THREADS 4
#define TMP_DIR "./tmp"

const char *get_registry_url();                                                      // 程序启动时调用。获取环境变量"REGISTRY"的值。若无则返回默认url
ParsedUri_t parse_uri(const char *uri);                                              // 解析uri，提取出registry, package, version
int download_tar(const char *tar_url, const char *outfile);                          // 下载url指向的tar包，保存为outfile
static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp);      // 解包tarball使用的回调函数，在download_tar中被调用
void server_doit(int connfd);                                                        // 供worker调用的处理函数，负责处理单个请求
void read_requesthdrs(rio_t *rp);                                                    // 读取请求头并发送到服务器终端的函数
void client_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg); // 发送错误信息到客户端
const char *get_content_type(const char *filename);                                  // 根据文件后缀返回对应的mime
void serve_file(int fd, const char *filepath);                                       // 发送文件内容到客户端
void serve_dir(int fd, const char *dirpath, const char *uri);                        // 发送目录列表到客户端
int compare_versions(const char *v1, const char *v2);                                // 比较两个版本号的大小，v1>v2返回1，v1==v2返回0，v1<v2返回-1
void url_decode(const char *src, char *dst);                                         // URL解码函数

// 多线程处理函数
void *worker(void *arg);

/*main begin*/
int main(int argc, char **argv)
{
    char client_hostname[MAXLINE], client_port[MAXLINE];
    int listenfd, connfd;
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }

    registry = get_registry_url();

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0)
    {
        fprintf(stderr, "curl global init failed\n");
        exit(1);
    }
    listenfd = Open_listenfd(argv[1]);
    sbuf_init(&sbuf, SBUF_SIZE);

    // 创建worker
    for (int i = 0; i < WORKER_THREADS; i++)
    {
        Pthread_create(&tid, NULL, worker, NULL);
    }

    // 接受新的accept请求，并将新的connfd插入到sbuf
    while (1)
    {
        clientlen = sizeof(struct sockaddr_storage);
        connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
        Getnameinfo((SA *)&clientaddr, clientlen, client_hostname, MAXLINE, client_port, MAXLINE, 0);
        printf("Accepted connection from (%s, %s)\n", client_hostname, client_port);
        sbuf_insert(&sbuf, connfd); // 将新的connfd插入到sbuf
    }
}

void *worker(void *arg)
{
    /*worker线程：取出connfd，处理，关闭*/
    while (1)
    {
        int connfd = sbuf_remove(&sbuf);
        if (connfd == -1)
        {
            break;
        }
        server_doit(connfd);
        Close(connfd);
    }
    return NULL;
}

const char *get_registry_url()
{
    /*从环境变量中获取REGISTRY，若没有则返回一个默认的url*/
    char *url = getenv("REGISTRY");
    if (url == NULL)
    {
        url = "https://registry.npmjs.org"; // 默认为此url
    }
    return url;
}

ParsedUri_t parse_uri(const char *uri)
{
    /*解析uri，提取出package, version, path, type*/
    ParsedUri_t res;
    memset(&res, 0, sizeof(ParsedUri_t));

    const char *ori = uri;

    if (uri[0] == '/')
        uri++;
    const char *pkg_start = uri;
    const char *pkg_end = NULL;
    const char *ver_start = NULL;
    const char *path_start = NULL;

    if (*pkg_start == '@')
    {
        const char *scope_slash = strchr(pkg_start + 1, '/'); // 跳过包头的@，寻找第一个斜杠开始包名
        if (scope_slash)
        {
            pkg_end = strchr(scope_slash + 1, '@'); // 在包名后寻找@，开始版本号
        }
    }
    else
    {
        // 非scope包，包名在第一个@前结束
        pkg_end = strchr(pkg_start, '@');
    }

    if (!pkg_end)
    {
        // 没有找到@，包名在第一个/前或末尾结束
        pkg_end = strchr(pkg_start, '/');
        if (!pkg_end)
        {
            pkg_end = pkg_start + strlen(pkg_start);
        }
    }
    strncpy(res.package, pkg_start, pkg_end - pkg_start);

    // 查找版本和路径
    ver_start = strchr(pkg_end, '@');
    if (ver_start)
    {
        // 找到了版本分隔符'@'
        path_start = strchr(ver_start + 1, '/');
        if (path_start)
        {
            // 有路径
            strncpy(res.version, ver_start + 1, path_start - (ver_start + 1));
            strcpy(res.path, path_start + 1);
        }
        else
        {
            // 只有版本，没有路径
            strcpy(res.version, ver_start + 1);
        }
    }
    else
    {
        // 没有找到版本分隔符'@'，版本默认为 "latest"
        strcpy(res.version, "latest");
        path_start = strchr(pkg_end, '/');
        if (path_start)
        {
            strcpy(res.path, path_start + 1);
        }
    }

    // 确定请求类型
    if (strlen(res.path) == 0)
    {
        if (ori[strlen(ori) - 1] == '/')
        {
            res.type = REQ_DIR;
        }
        else
        {
            res.type = ENTRY;
        }
    }
    else if (res.path[strlen(res.path) - 1] == '/')
    {
        res.type = REQ_DIR;
    }
    else
    {
        res.type = REQ_FILE;
    }

    return res;
}

int download_tar(const char *tar_url, const char *outfile)
{
    /*使用libcurl下载指定的tar包，并存储到outfile。发生任何错误则返回-1，完成返回0*/
    struct Membuffer chunk;
    memset(&chunk, 0, sizeof(struct Membuffer));

    // 使用libcurl下载tar
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    curl_easy_setopt(curl, CURLOPT_URL, tar_url);
    // 经测试使用 禁用ssl验证
    // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    // 测试使用代码结束（未解决问题）
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl failed: %s\n", curl_easy_strerror(res));
        free(chunk.data);
        return -1;
    }

    // 用libarchive抽取tar
    struct archive *a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);

    if (archive_read_open_memory(a, chunk.data, chunk.size) != ARCHIVE_OK)
    {
        fprintf(stderr, "archive open failed: %s\n", archive_error_string(a));
        free(chunk.data);
        archive_read_free(a);
        return -1;
    }

    struct archive *ext = archive_write_disk_new();
    // opt: 使用归档时间戳 | 使用归档文件权限 | 使用归档ACL | 使用归档文件标志
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
    /* （ai写的）使用标准用户/组名解析（如果可用）*/
    archive_write_disk_set_standard_lookup(ext);

    struct archive_entry *entry;
    char pathbuffer[1026];
    /* 计算解包目录：将 outfile 的尾部后缀（如 .tar.gz）去掉，作为目录名 */
    char outdir[1024];
    strncpy(outdir, outfile, sizeof(outdir) - 1);
    outdir[sizeof(outdir) - 1] = '\0';
    size_t olen = strlen(outdir);
    if (olen > 7 && strcmp(outdir + olen - 7, ".tar.gz") == 0)
    {
        outdir[olen - 7] = '\0';
    }
    else
    {
        char *dot = strrchr(outdir, '.');
        if (dot)
            *dot = '\0';
    }

    if (mkdir(outdir, 0755) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "failed to create outdir %s: %s\n", outdir, strerror(errno));
        archive_write_close(ext);
        archive_write_free(ext);
        archive_read_close(a);
        archive_read_free(a);
        free(chunk.data);
        return -1;
    }
    int r = 0;
    while (1)
    {
        int hret = archive_read_next_header(a, &entry);
        if (hret == ARCHIVE_EOF)
            break;
        if (hret != ARCHIVE_OK)
        {
            fprintf(stderr, "archive header read error: %s\n", archive_error_string(a));
            break;
        }

        const char *currentfile = archive_entry_pathname(entry);
        /* 基本安全检查：禁止绝对路径和路径穿越 */
        if (currentfile == NULL || currentfile[0] == '/' || strstr(currentfile, ".."))
        {
            fprintf(stderr, "skipping unsafe path: %s\n", currentfile ? currentfile : "(null)");
            continue;
        }

        // 生成输出路径: outdir/currentfile
        snprintf(pathbuffer, sizeof(pathbuffer), "%s/%s", outdir, currentfile);
        archive_entry_set_pathname(entry, pathbuffer);

        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK)
        {
            fprintf(stderr, "write header failed: %s\n", archive_error_string(ext));
            // 继续处理下一个 entry
            continue;
        }
        else
        {
            const void *buff;
            size_t size;
            la_int64_t offset;

            while (1)
            {
                int dret = archive_read_data_block(a, &buff, &size, &offset);
                if (dret == ARCHIVE_EOF)
                    break;
                if (dret != ARCHIVE_OK)
                {
                    fprintf(stderr, "read data block error: %s\n", archive_error_string(a));
                    break;
                }
                if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK)
                {
                    fprintf(stderr, "write data block error: %s\n", archive_error_string(ext));
                    break;
                }
            }
            archive_write_finish_entry(ext);
        }
    }

    // 完成后清理打开的缓冲区
    archive_write_close(ext);
    archive_write_free(ext);
    archive_read_close(a);
    archive_read_free(a);
    free(chunk.data);

    return 0;
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct Membuffer *mem = (struct Membuffer *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr)
        return 0;

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize); // 将新数据复制到data末尾
    mem->size += realsize;                               // 更新数据大小
    /* NUL 终止，方便后续作为字符串处理 */
    mem->data[mem->size] = '\0';
    return realsize;
}

const char *get_content_type(const char *filename)
{
    /*根据filename返回对应的mime*/
    if (strstr(filename, ".html"))
        return "text/html; charset=utf-8";
    if (strstr(filename, ".css"))
        return "text/css; charset=utf-8";
    if (strstr(filename, ".js"))
        return "application/javascript; charset=utf-8";
    if (strstr(filename, ".json"))
        return "application/json; charset=utf-8";
    if (strstr(filename, ".png"))
        return "image/png";
    if (strstr(filename, ".jpg") || strstr(filename, ".jpeg"))
        return "image/jpeg";
    if (strstr(filename, ".gif"))
        return "image/gif";
    if (strstr(filename, ".svg"))
        return "image/svg+xml";
    return "text/plain; charset=utf-8"; // 默认
}

void serve_file(int fd, const char *filepath)
{
    /*返回文件内容，构造http响应*/
    char filetype[MAXLINE], buf[MAXBUF];
    int filefd;
    struct stat sbuf;

    if (stat(filepath, &sbuf) < 0)
    {
        client_error(fd, filepath, "404", "Not Found", "Server couldn't find this file");
        return;
    }

    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
    {
        client_error(fd, filepath, "403", "Forbidden", "Server couldn't read this file");
        return;
    }

    strcpy(filetype, get_content_type(filepath));
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    sprintf(buf, "%sContent-length: %ld\r\n", buf, sbuf.st_size);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);
    Rio_writen(fd, buf, strlen(buf));
    printf("Response headers:\n%s", buf);

    filefd = Open(filepath, O_RDONLY, 0);
    char *srcp = Mmap(0, sbuf.st_size, PROT_READ, MAP_PRIVATE, filefd, 0);
    Close(filefd);
    Rio_writen(fd, srcp, sbuf.st_size);
    Munmap(srcp, sbuf.st_size);
}

void serve_dir(int fd, const char *dirpath, const char *uri)
{
    char buf[MAXBUF], entry_buf[MAXLINE], decoded_uri[MAXLINE];
    DIR *dir;
    struct dirent *entry;

    url_decode(uri, decoded_uri);
    dir = opendir(dirpath);
    if (dir == NULL)
    {
        client_error(fd, dirpath, "404", "Not Found", "Could not open directory");
        return;
    }

    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(buf, "%sContent-type: text/html; charset=utf-8\r\n\r\n", buf);
    Rio_writen(fd, buf, strlen(buf));

    sprintf(buf, "<html><head><title>Index of %s</title></head><body>", decoded_uri);
    sprintf(buf, "%s<h1>Index of %s</h1><hr><ul>", buf, decoded_uri);
    Rio_writen(fd, buf, strlen(buf));

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // 判断是目录还是文件，在目录链接后加斜杠
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        struct stat sbuf;
        stat(full_path, &sbuf);
        if (S_ISDIR(sbuf.st_mode))
        {
            sprintf(entry_buf, "<li><a href=\"%s/\">%s/</a></li>", entry->d_name, entry->d_name);
        }
        else
        {
            sprintf(entry_buf, "<li><a href=\"%s\">%s</a></li>", entry->d_name, entry->d_name);
        }
        Rio_writen(fd, entry_buf, strlen(entry_buf));
    }
    closedir(dir);

    sprintf(buf, "</ul><hr></body></html>");
    Rio_writen(fd, buf, strlen(buf));
}
void server_doit(int connfd)
{
    rio_t rio;
    char buffer[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char decoded_uri[MAXLINE];

    Rio_readinitb(&rio, connfd);
    if (!Rio_readlineb(&rio, buffer, MAXLINE))
        return;

    sscanf(buffer, "%s %s %s", method, uri, version);
    if (strcasecmp(method, "GET"))
    {
        client_error(connfd, method, "501", "Not Implemented", "Server does not implement this method");
        return;
    }

    // 在解析前对uri调用解码函数
    url_decode(uri, decoded_uri);
    // DEBUG: printf
    printf("decoded uri: %s\n", decoded_uri);

    read_requesthdrs(&rio);

    // 1. 解析URI
    ParsedUri_t parsed_uri = parse_uri(decoded_uri);
    if (strlen(parsed_uri.package) == 0)
    {
        client_error(connfd, decoded_uri, "400", "Bad Request", "Could not parse package name");
        return;
    }

    // 2. 构造本地路径
    char safe_package_name[sizeof(parsed_uri.package)];
    strncpy(safe_package_name, parsed_uri.package, sizeof(safe_package_name));
    for (char *p = safe_package_name; *p; p++)
    {
        if (*p == '/')
            *p = '_';
    }

    char outdir[MAXLINE];
    snprintf(outdir, sizeof(outdir), "%s/%s-%s", TMP_DIR, safe_package_name, parsed_uri.version);

    char target_filepath_a[MAXLINE];
    snprintf(target_filepath_a, sizeof(target_filepath_a), "%s/%s", outdir, parsed_uri.path);

    // 3. 检查缓存是否存在，如果不存在则下载
    struct stat sbuf;
    if (stat(outdir, &sbuf) != 0 || !S_ISDIR(sbuf.st_mode))
    {
        printf("Cache miss for %s. Downloading...\n", outdir);

        // 构造registry url
        char reg_url[MAXLINE];
        snprintf(reg_url, sizeof(reg_url), "%s/%s", registry, parsed_uri.package);

        struct Membuffer resp = {0};
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            return;
        }
        curl_easy_setopt(curl, CURLOPT_URL, reg_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        CURLcode cres = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);

        if (cres != CURLE_OK || http_code != 200 || !resp.data)
        {
            client_error(connfd, reg_url, "502", "Bad Gateway", "Failed to fetch metadata");
            free(resp.data);
            return;
        }

        char tarball_url[MAXLINE] = {0};
        cJSON *json = cJSON_Parse(resp.data);
        if (!json)
        {
            free(resp.data);
            return;
        }

        cJSON *versions = cJSON_GetObjectItem(json, "versions");
        if (!versions)
        {
            cJSON_Delete(json);
            free(resp.data);
            return;
        }

        cJSON *target_version_json = NULL;
        char actual_version[64] = {0};
        strcpy(actual_version, parsed_uri.version);

        if (strcmp(parsed_uri.version, "latest") == 0)
        {
            // 从metadata中找到dist-tags
            cJSON *dist_tags = cJSON_GetObjectItem(json, "dist-tags");
            if (dist_tags)
            {
                // 从dist-tags中找到latest字段，并取其值
                cJSON *latest_version_item = cJSON_GetObjectItem(dist_tags, "latest");
                if (latest_version_item && cJSON_IsString(latest_version_item))
                {
                    // 将获取到的版本号存入actual_version中，此时对应的版本就是latest
                    strcpy(actual_version, latest_version_item->valuestring);
                    // 查找对应的版本
                    target_version_json = cJSON_GetObjectItem(versions, actual_version);
                }
            }
        }
        else if (parsed_uri.version[0] == '^' || parsed_uri.version[0] == '~')
        {
            char range_type = parsed_uri.version[0]; // 取出范围符号
            const char *base_version = parsed_uri.version + 1;
            int base_major = 0, base_minor = 0, base_patch = 0; // 基础版本号
            sscanf(base_version, "%d.%d.%d", &base_major, &base_minor, &base_patch);

            char matched_version[64] = {0};
            cJSON *current_version_obj = NULL;
            cJSON_ArrayForEach(current_version_obj, versions)
            {
                const char *current_version_str = current_version_obj->string;
                int cur_major = 0, cur_minor = 0, cur_patch = 0;
                sscanf(current_version_str, "%d.%d.%d", &cur_major, &cur_minor, &cur_patch);

                // 检查遍历到的条目是否满足条件
                bool is_matched = false;
                if (compare_versions(current_version_str, base_version) >= 0)
                {
                    if (range_type == '^' && cur_major == base_major)
                    {
                        is_matched = true;
                    }
                    else if (range_type == '~' && cur_major == base_major && cur_minor == base_minor)
                    {
                        is_matched = true;
                    }
                }
                if (is_matched)
                {
                    if (strlen(matched_version) == 0 || compare_versions(current_version_str, matched_version) > 0)
                    {
                        strcpy(matched_version, current_version_str);
                    }
                }
            }
            if (strlen(matched_version) > 0)
            {
                strcpy(actual_version, matched_version);
            }
        }
        else
        {
            cJSON *dist_tags = cJSON_GetObjectItem(json, "dist-tags");
            cJSON *tag_item = NULL;
            if (dist_tags)
            {
                tag_item = cJSON_GetObjectItem(dist_tags, parsed_uri.version);
            }

            if (tag_item && cJSON_IsString(tag_item))
            {
                strcpy(actual_version, tag_item->valuestring);
            }
            else
            {
                strcpy(actual_version, parsed_uri.version);
            }
        }
        if (strlen(actual_version) > 0)
        {
            // 最后用actual_version去versions中查找对应的版本
            target_version_json = cJSON_GetObjectItem(versions, actual_version);
        }

        if (!target_version_json)
        {
            cJSON_Delete(json);
            free(resp.data);
            return;
        }

        // 更新 outdir 和 target_filepath 以使用确切的版本号
        snprintf(outdir, sizeof(outdir), "%s/%s-%s", TMP_DIR, safe_package_name, actual_version);
        snprintf(target_filepath_a, sizeof(target_filepath_a), "%s/%s", outdir, parsed_uri.path);

        cJSON *dist = cJSON_GetObjectItem(target_version_json, "dist");
        cJSON *tarball_item = dist ? cJSON_GetObjectItem(dist, "tarball") : NULL;
        if (!tarball_item || !cJSON_IsString(tarball_item))
        { /* ... 错误处理 ... */
            cJSON_Delete(json);
            free(resp.data);
            return;
        }

        strncpy(tarball_url, tarball_item->valuestring, sizeof(tarball_url) - 1);

        char outfile[MAXLINE];
        snprintf(outfile, sizeof(outfile), "%s.tar.gz", outdir);

        if (download_tar(tarball_url, outfile) != 0)
        {
            client_error(connfd, tarball_url, "502", "Bad Gateway", "download/extract failed");
            cJSON_Delete(json);
            free(resp.data);
            return;
        }
        cJSON_Delete(json);
        free(resp.data);
    }
    else
    {
        printf("Cache hit for %s.\n", outdir);
    }

    // 4. 根据请求类型提供服务  DEBUG: 添加'puckage/'目录的情况
    char target_filepath[MAXLINE];
    snprintf(target_filepath, sizeof(target_filepath), "%s/package/%s", outdir, parsed_uri.path);

    // 如果在package目录下找不到，再尝试根目录
    if (stat(target_filepath, &sbuf) != 0)
    {
        snprintf(target_filepath, sizeof(target_filepath), "%s/%s", outdir, parsed_uri.path);
    }

    // 再根据type请求正确的服务
    if (parsed_uri.type == ENTRY)
    {
        // --- 入口点解析逻辑 ---
        char package_json_path[MAXLINE];
        snprintf(package_json_path, sizeof(package_json_path), "%s/package/package.json", outdir);

        // npm 包解压后通常会有一个 'package' 子目录。如果package.json不在这里，则尝试上一级目录
        if (stat(package_json_path, &sbuf) != 0)
        {
            snprintf(package_json_path, sizeof(package_json_path), "%s/package.json", outdir);
        }

        char entry_point_path[MAXLINE] = "index.js"; // 默认返回index.js
        FILE *f = fopen(package_json_path, "r");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            long len = ftell(f);
            fseek(f, 0, SEEK_SET);
            char *pkg_content = malloc(len + 1);
            fread(pkg_content, 1, len, f);
            fclose(f);
            pkg_content[len] = '\0';

            cJSON *pkg_json = cJSON_Parse(pkg_content);
            if (pkg_json)
            {
                cJSON *exports = cJSON_GetObjectItem(pkg_json, "exports");
                cJSON *main = cJSON_GetObjectItem(pkg_json, "main");
                if (exports)
                {
                    cJSON *dot_export = cJSON_GetObjectItem(exports, ".");
                    if (dot_export)
                    {
                        if (cJSON_IsString(dot_export))
                        {
                            strcpy(entry_point_path, dot_export->valuestring);
                        }
                        else if (cJSON_IsObject(dot_export))
                        {
                            cJSON *default_export = cJSON_GetObjectItem(dot_export, "default");
                            if (default_export && cJSON_IsString(default_export))
                            {
                                strcpy(entry_point_path, default_export->valuestring);
                            }
                        }
                    }
                }
                else if (main && cJSON_IsString(main))
                {
                    strcpy(entry_point_path, main->valuestring);
                }
                cJSON_Delete(pkg_json);
            }
            free(pkg_content);
        }

        // 修正入口点路径，去掉开头的 './'
        if (strncmp(entry_point_path, "./", 2) == 0)
        {
            memmove(entry_point_path, entry_point_path + 2, strlen(entry_point_path) - 1);
        }

        snprintf(target_filepath, sizeof(target_filepath), "%s/package/%s", outdir, entry_point_path);
        if (stat(target_filepath, &sbuf) != 0)
        {
            snprintf(target_filepath, sizeof(target_filepath), "%s/%s", outdir, entry_point_path);
        }
        serve_file(connfd, target_filepath);
    }
    else if (parsed_uri.type == REQ_DIR)
    {
        serve_dir(connfd, target_filepath, uri);
    }
    else // REQ_FILE
    {
        serve_file(connfd, target_filepath);
    }
}

void read_requesthdrs(rio_t *rp)
{
    char buf[MAXLINE];

    while (Rio_readlineb(rp, buf, MAXLINE) > 0 && strcmp(buf, "\r\n")) // 直到读到空行结束
    {
        printf("%s", buf);
    }
    return;
}

void client_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg)
{
    char buf[MAXLINE];

    /* Print the HTTP response headers */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n\r\n");
    Rio_writen(fd, buf, strlen(buf));

    /* Print the HTTP response body */
    sprintf(buf, "<html><title>Tiny Error</title>");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<body bgcolor="
                 "ffffff"
                 ">\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "%s: %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<p>%s: %s\r\n", longmsg, cause);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<hr><em>The Tiny Web server</em>\r\n");
    Rio_writen(fd, buf, strlen(buf));
}

int compare_versions(const char *v1, const char *v2)
{
    int major1 = 0, minor1 = 0, patch1 = 0;
    int major2 = 0, minor2 = 0, patch2 = 0;

    sscanf(v1, "%d.%d.%d", &major1, &minor1, &patch1);
    sscanf(v2, "%d.%d.%d", &major2, &minor2, &patch2);

    if (major1 != major2)
        return (major1 > major2) ? 1 : -1;
    if (minor1 != minor2)
        return (minor1 > minor2) ? 1 : -1;
    if (patch1 != patch2)
        return (patch1 > patch2) ? 1 : -1;
    return 0;
}

void url_decode(const char *src, char *dst)
{
    char a, b;
    while (*src)
    {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b)))
        {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        }
        else if (*src == '+')
        {
            *dst++ = ' ';
            src++;
        }
        else
        {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}