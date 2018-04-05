insert_crl_info_query = '''INSERT INTO crl_info
  SET
`server` = %(server)s,
subjKeyId = %(subjKeyId)s,
crl_CN = %(crl_CN)s,
crl_O = %(crl_O)s,
thisUpdateDatetime = %(thisUpdateDatetime)s,
nextUpdateDatetime = %(nextUpdateDatetime)s,
lastUrlModificationDatetime = %(lastUrlModificationDatetime)s,
insertDatetime = NOW(),
url = %(url)s,
crlFileName = %(crlFileName)s,
crlFileLocation = %(crlFileLocation)s,
`crlFileHash` = %(crlFileHash)s,
`status` = %(status)s
  ;'''

delete_server_info_query = '''DELETE FROM crl_info WHERE `server` = %s;'''


get_crl_file_location_by_subj_key_id_query = '''SELECT ci.crlFileLocation
  FROM crl_info ci
WHERE ci.subjKeyId = '%s'
  LIMIT 1
  ;'''


get_file_locations_for_delete_query = '''SELECT
  ci.crlFileLocation
FROM crl_info ci
 WHERE ci.insertDatetime < SUBDATE(DATE(NOW()), INTERVAL %s DAY)
 AND `server` = %s
 AND noDelete = 0
 AND archive = 0
;'''

delete_old_bd_record_query = '''DELETE
  FROM crl_info
 WHERE insertDatetime < SUBDATE(DATE(NOW()), INTERVAL %s DAY)
 AND `server` = %s
 AND noDelete = 0
 AND archive = 0
;'''

get_urls_by_subj_key_and_server = '''SELECT
  DISTINCT ci.url
FROM crl_info ci
WHERE ci.subjKeyId = %s
 AND ci.server = %s
 AND archive = 0
;'''