#ifndef APOLLO_SECURITY_AUDIT_H
#define APOLLO_SECURITY_AUDIT_H

#include "types.h"

#define SECURITY_AUDIT_MAX_ISSUES 256
#define SECURITY_AUDIT_MAX_RECOMMENDATIONS 128

typedef enum {
    SECURITY_SEVERITY_INFO = 0,
    SECURITY_SEVERITY_LOW = 1,
    SECURITY_SEVERITY_MEDIUM = 2,
    SECURITY_SEVERITY_HIGH = 3,
    SECURITY_SEVERITY_CRITICAL = 4
} security_severity_t;

typedef enum {
    SECURITY_CAT_CONFIGURATION = 0,
    SECURITY_CAT_AUTHENTICATION = 1,
    SECURITY_CAT_ENCRYPTION = 2,
    SECURITY_CAT_NETWORK = 3,
    SECURITY_CAT_ACCESS_CONTROL = 4,
    SECURITY_CAT_LOGGING = 5,
    SECURITY_CAT_SYSTEM = 6
} security_category_t;

typedef struct {
    uint32_t issue_id;
    security_severity_t severity;
    security_category_t category;
    char title[128];
    char description[512];
    char recommendation[256];
    bool is_exploitable;
    uint32_t risk_score;  // 0-100
} security_issue_t;

typedef struct {
    security_issue_t issues[SECURITY_AUDIT_MAX_ISSUES];
    uint32_t issue_count;
    
    uint32_t critical_count;
    uint32_t high_count;
    uint32_t medium_count;
    uint32_t low_count;
    uint32_t info_count;
    
    uint32_t overall_score;  // 0 to 100, higher is better
    bool audit_passed;
    
    uint32_t audit_time;
    char audit_version[32];
} security_audit_result_t;

bool security_audit_initialize(void);
security_audit_result_t* security_audit_run_full_scan(void);
security_audit_result_t* security_audit_run_quick_scan(void);
security_audit_result_t* security_audit_run_network_scan(void);
void security_audit_print_summary(const security_audit_result_t* result);
void security_audit_print_detailed_report(const security_audit_result_t* result);
bool security_audit_start_continuous_monitoring(void);
void security_audit_stop_continuous_monitoring(void);
void security_audit_periodic(void);

#endif