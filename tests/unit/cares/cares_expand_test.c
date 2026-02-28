#include <ares.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Test c-ares ability to expand DNS compression pointers.
 * 
 * DNS compression uses pointers to reference earlier domain names:
 * - Pointer format: 2 bytes, first byte has high 2 bits = 11 (0xC0 | offset_high)
 * - Example: 0xC0 0x0C points to offset 12 in the packet
 * 
 * Test case:
 * - Question: example.com
 * - Answer: example.com -> 93.184.215.14 (using compression pointer for name)
 */

/* Build a DNS response packet with compression pointer */
static size_t build_compressed_dns_response(uint8_t* buf, size_t buf_size) {
    /*
     * DNS Response structure:
     * 
     * Header (12 bytes):
     *   ID: 0x1234
     *   Flags: QR=1, AA=1, RD=1, RA=1 -> 0x8180
     *   QDCOUNT: 1
     *   ANCOUNT: 1
     *   NSCOUNT: 0
     *   ARCOUNT: 0
     * 
     * Question (offset 12):
     *   QNAME: 7example3com0 -> "example.com"
     *   QTYPE: A (1)
     *   QCLASS: IN (1)
     * 
     * Answer (offset 12 + 7 + 4 + 1 + 4 = offset 28):
     *   NAME: 0xC0 0x0C (pointer to offset 12, i.e., "example.com")
     *   TYPE: A (1)
     *   CLASS: IN (1)
     *   TTL: 3600
     *   RDLENGTH: 4
     *   RDATA: 93.184.215.14
     */

    memset(buf, 0, buf_size);
    size_t offset = 0;

    /* Header */
    buf[offset++] = 0x12;
    buf[offset++] = 0x34; /* ID */
    buf[offset++] = 0x81;
    buf[offset++] = 0x80; /* Flags: QR=1, AA=1, RD=1, RA=1 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* QDCOUNT: 1 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* ANCOUNT: 1 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; /* NSCOUNT: 0 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; /* ARCOUNT: 0 */

    /* Question: "example.com" */
    size_t qname_offset = offset; /* Save for compression pointer */
    buf[offset++] = 7; /* Length of "example" */
    memcpy(buf + offset, "example", 7);
    offset += 7;
    buf[offset++] = 3; /* Length of "com" */
    memcpy(buf + offset, "com", 3);
    offset += 3;
    buf[offset++] = 0; /* Null terminator */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* QTYPE: A */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* QCLASS: IN */

    /* Answer: using compression pointer */
    buf[offset++] = 0xC0; /* Compression pointer marker */
    buf[offset++] = (uint8_t)qname_offset; /* Points to "example.com" at offset 12 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* TYPE: A */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* CLASS: IN */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x0E;
    buf[offset++] = 0x10; /* TTL: 3600 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x04; /* RDLENGTH: 4 */
    buf[offset++] = 93;
    buf[offset++] = 184;
    buf[offset++] = 215;
    buf[offset++] = 14; /* IP: 93.184.215.14 */

    return offset;
}

/* Build a DNS response with nested compression (CNAME case) */
static size_t build_nested_compressed_dns_response(uint8_t* buf, size_t buf_size) {
    /*
     * More complex case:
     * - Question: www.example.com
     * - Answer 1: www.example.com -> example.com (CNAME, using compression)
     * - Answer 2: example.com -> 93.184.215.14 (A, using compression)
     * 
     * This tests:
     * 1. Answer name points to question name
     * 2. CNAME RDATA points to earlier name
     * 3. Second answer name points via compression
     */

    memset(buf, 0, buf_size);
    size_t offset = 0;

    /* Header */
    buf[offset++] = 0x12;
    buf[offset++] = 0x34; /* ID */
    buf[offset++] = 0x81;
    buf[offset++] = 0x80; /* Flags */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* QDCOUNT: 1 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x02; /* ANCOUNT: 2 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; /* NSCOUNT: 0 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; /* ARCOUNT: 0 */

    /* Question: "www.example.com" */
    size_t qname_offset = offset;
    buf[offset++] = 3;
    memcpy(buf + offset, "www", 3);
    offset += 3;
    size_t example_com_offset = offset; /* Save for later compression */
    buf[offset++] = 7;
    memcpy(buf + offset, "example", 7);
    offset += 7;
    buf[offset++] = 3;
    memcpy(buf + offset, "com", 3);
    offset += 3;
    buf[offset++] = 0;
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* QTYPE: A */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* QCLASS: IN */

    /* Answer 1: www.example.com -> example.com (CNAME) */
    buf[offset++] = 0xC0;
    buf[offset++] = (uint8_t)qname_offset; /* www.example.com */
    buf[offset++] = 0x00;
    buf[offset++] = 0x05; /* TYPE: CNAME */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* CLASS: IN */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x03;
    buf[offset++] = 0x84; /* TTL: 900 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x02; /* RDLENGTH: 2 (compression pointer only) */
    buf[offset++] = 0xC0;
    buf[offset++] = (uint8_t)example_com_offset; /* example.com (compressed) */

    /* Answer 2: example.com -> 93.184.215.14 (A) */
    buf[offset++] = 0xC0;
    buf[offset++] = (uint8_t)example_com_offset; /* example.com */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* TYPE: A */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; /* CLASS: IN */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x0E;
    buf[offset++] = 0x10; /* TTL: 3600 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x04; /* RDLENGTH: 4 */
    buf[offset++] = 93;
    buf[offset++] = 184;
    buf[offset++] = 215;
    buf[offset++] = 14;

    return offset;
}

static int test_simple_compression(void) {
    uint8_t packet[512];
    size_t pkt_len = build_compressed_dns_response(packet, sizeof(packet));
    ares_dns_record_t* dnsrec = NULL;

    printf("=== Test 1: Simple Compression Pointer ===\n");
    printf("Packet length: %zu bytes\n", pkt_len);

    ares_status_t status = ares_dns_parse(packet, pkt_len, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "FAIL: ares_dns_parse failed: %s\n", ares_strerror(status));
        return 1;
    }

    /* Verify question */
    const char* qname;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t qclass;

    status = ares_dns_record_query_get(dnsrec, 0, &qname, &qtype, &qclass);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "FAIL: Failed to get question: %s\n", ares_strerror(status));
        ares_dns_record_destroy(dnsrec);
        return 1;
    }

    printf("Question: %s (type=%d, class=%d)\n", qname, qtype, qclass);

    if (strcmp(qname, "example.com") != 0) {
        fprintf(stderr, "FAIL: Expected 'example.com', got '%s'\n", qname);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }
    printf("  Question name expansion: PASS\n");

    /* Verify answer */
    size_t ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    if (ancount != 1) {
        fprintf(stderr, "FAIL: Expected 1 answer, got %zu\n", ancount);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }

    const ares_dns_rr_t* rr = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 0);
    const char* rr_name = ares_dns_rr_get_name(rr);
    unsigned int ttl = ares_dns_rr_get_ttl(rr);

    printf("Answer: %s (type=%d, ttl=%u)\n", rr_name, ares_dns_rr_get_type(rr), ttl);

    if (strcmp(rr_name, "example.com") != 0) {
        fprintf(stderr, "FAIL: Expected answer name 'example.com', got '%s'\n", rr_name);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }
    printf("  Answer name expansion: PASS\n");

    /* Verify IP address */
    const struct in_addr* addr = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
    if (!addr) {
        fprintf(stderr, "FAIL: Failed to get A address\n");
        ares_dns_record_destroy(dnsrec);
        return 1;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
    printf("  IP address: %s\n", ip_str);

    if (strcmp(ip_str, "93.184.215.14") != 0) {
        fprintf(stderr, "FAIL: Expected IP '93.184.215.14', got '%s'\n", ip_str);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }
    printf("  IP address: PASS\n");

    ares_dns_record_destroy(dnsrec);
    printf("Test 1: PASSED\n\n");
    return 0;
}

static int test_nested_compression(void) {
    uint8_t packet[512];
    size_t pkt_len = build_nested_compressed_dns_response(packet, sizeof(packet));
    ares_dns_record_t* dnsrec = NULL;

    printf("=== Test 2: Nested Compression (CNAME chain) ===\n");
    printf("Packet length: %zu bytes\n", pkt_len);

    ares_status_t status = ares_dns_parse(packet, pkt_len, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "FAIL: ares_dns_parse failed: %s\n", ares_strerror(status));
        return 1;
    }

    /* Verify question */
    const char* qname;
    ares_dns_record_query_get(dnsrec, 0, &qname, NULL, NULL);
    printf("Question: %s\n", qname);

    if (strcmp(qname, "www.example.com") != 0) {
        fprintf(stderr, "FAIL: Expected 'www.example.com', got '%s'\n", qname);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }
    printf("  Question name expansion: PASS\n");

    /* Verify answers */
    size_t ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    printf("Answer count: %zu\n", ancount);

    if (ancount != 2) {
        fprintf(stderr, "FAIL: Expected 2 answers, got %zu\n", ancount);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }

    /* Answer 1: CNAME */
    const ares_dns_rr_t* rr1 = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 0);
    const char* rr1_name = ares_dns_rr_get_name(rr1);
    printf("Answer 1: %s (type=%d)\n", rr1_name, ares_dns_rr_get_type(rr1));

    if (ares_dns_rr_get_type(rr1) != ARES_REC_TYPE_CNAME) {
        fprintf(stderr, "FAIL: Expected CNAME record\n");
        ares_dns_record_destroy(dnsrec);
        return 1;
    }

    const char* cname_target = ares_dns_rr_get_str(rr1, ARES_RR_CNAME_CNAME);
    printf("  CNAME target: %s\n", cname_target);

    if (strcmp(cname_target, "example.com") != 0) {
        fprintf(stderr, "FAIL: Expected CNAME target 'example.com', got '%s'\n", cname_target);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }
    printf("  CNAME target expansion: PASS\n");

    /* Answer 2: A */
    const ares_dns_rr_t* rr2 = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 1);
    const char* rr2_name = ares_dns_rr_get_name(rr2);
    printf("Answer 2: %s (type=%d)\n", rr2_name, ares_dns_rr_get_type(rr2));

    if (strcmp(rr2_name, "example.com") != 0) {
        fprintf(stderr, "FAIL: Expected answer name 'example.com', got '%s'\n", rr2_name);
        ares_dns_record_destroy(dnsrec);
        return 1;
    }
    printf("  Answer name expansion: PASS\n");

    ares_dns_record_destroy(dnsrec);
    printf("Test 2: PASSED\n\n");
    return 0;
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    ares_status_t ret = ares_library_init(ARES_LIB_INIT_ALL);
    if (ret != ARES_SUCCESS) {
        fprintf(stderr, "Failed to initialize c-ares: %s\n", ares_strerror(ret));
        return EXIT_FAILURE;
    }

    int failed = 0;
    failed += test_simple_compression();
    failed += test_nested_compression();

    ares_library_cleanup();

    if (failed == 0) {
        return EXIT_SUCCESS;
    } else {
        printf("=== %d test(s) FAILED ===\n", failed);
        return EXIT_FAILURE;
    }
}
