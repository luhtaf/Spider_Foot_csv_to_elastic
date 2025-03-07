SELECT DISTINCT
        si.name as 'SCAN_NAME',
        sr.*,
        SUBSTR(sr.data, 1, INSTR(sr.data || CHAR(10), CHAR(10)) - 1) as Vulnerability,
        CASE 
            WHEN scr.title LIKE '%: %' THEN SUBSTR(scr.title, INSTR(scr.title, ': ') + 2)
            WHEN scr.title LIKE '%on %' THEN SUBSTR(scr.title, INSTR(scr.title, 'on ') + 3)
        END as IP_Addresses
    FROM 
        tbl_scan_results sr
    JOIN 
        tbl_scan_correlation_results_events scre ON sr.hash = scre.event_hash
    JOIN 
        tbl_scan_correlation_results scr ON scre.correlation_id = scr.id
    JOIN 
        tbl_scan_instance si ON scr.scan_instance_id = si.guid
    WHERE 
        sr.type LIKE 'VULNERABILITY_CVE_%'
        AND sr.generated > ?
    GROUP BY 
        sr.hash
    ORDER BY 
        sr.data 
    LIMIT 100