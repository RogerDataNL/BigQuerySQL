/*
  <PURPOSE>
  Enrich the BigQuery audit log with additional columns to make query grouping possible. Most important use case would be for usage costs optimization
    </PURPOSE>
  <USAGE>
  -1st, setup streaming your BigQuery audit log to a table (in BigQuery): https://cloud.google.com/bigquery/audit-logs
  -2nd, change the project / dataset in the <QUERY_REPLACE> tag and run / test the query, then save as view
  -3rd, using the view, write aggregate-style queries over the log, using the new columns. Remember to filter on the [LogDate] column to limit
  This Query was especially made with LOOKER in mind as a BI end user tool, but the pattern applied should also work for other tools that genererate / push down SQL
	</USAGE>
  <AUTHOR>Rogier Werschkull (RogerData)</AUTHOR>
	<LAST_UPDATE>22-01-2019</LAST_UPDATE>
*/
WITH
  vw AS (
  SELECT
    timestamp AS Date,
    _TABLE_SUFFIX AS LogDate,
    resource.labels.project_id AS ProjectId,
    protopayload_auditlog.serviceName AS ServiceName,
    protopayload_auditlog.methodName AS MethodName,
    protopayload_auditlog.status.code AS StatusCode,
    protopayload_auditlog.status.message AS StatusMessage,
    protopayload_auditlog.authenticationInfo.principalEmail AS UserId,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobName.jobId AS JobId,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.query AS Query,
    --<QUERY_COMMENT>LOGIC FOR QUERY GROUPING: Clean the query.query SQL text to minimize the amount of repeating query patterns:
    ----replace ANY SQL query date filter with the static string: YYYY-MM-DD
    ----FOR LOOKER GENERATED QUERIES: remove the looker LR table HASH string 
    REGEXP_REPLACE( REGEXP_REPLACE(protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.query, r"'\d{4}-?\d{2}-?\d{2}'",'\`YYYY-MM-DD\''),r"LR_[A-Z0-9]+?_",'LR_') AS CleanQuery,
    --</QUERY_COMMENT>
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.destinationTable.projectId AS DestinationTableProjectId,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.destinationTable.datasetId AS DestinationTableDatasetId,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.destinationTable.tableId AS DestinationTableId,
    --<QUERY_COMMENT>LOGIC FOR QUERY GROUPING: Clean the destinationTable.tableId to minimize the amount of repeating query patterns (Only when writing to real tables (=NOT anon in prefix)):
    -----Remove the temp large results table HASH prefixes
    -----FOR LOOKER GENERATED QUERIES: Rename Looker LC table to LR & strip the HASH PREFIX from the name
    -----remove time partitioning suffix
    CASE
      WHEN protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.destinationTable.tableId NOT LIKE 'anon%' THEN REGEXP_REPLACE(REGEXP_REPLACE(REGEXP_REPLACE( protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.destinationTable.tableId, r"^tmp_large_results_.*",'tmp_large_results_HASH'), r"^LC_[A-Z0-9]+?_",'LR_'), r"\$[0-9]+",'')
    END AS CleanDestinationTableId,
    --</QUERY_COMMENT>
    REGEXP_EXTRACT(protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.destinationTable.tableId, r"\$[0-9]+") AS DestinationTableTimePartition,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.createDisposition AS CreateDisposition,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.query.writeDisposition AS WriteDisposition,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobConfiguration.dryRun AS DryRun,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatus.state AS JobState,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatus.error.code AS JobErrorCode,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatus.error.message AS JobErrorMessage,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.createTime AS JobCreateTime,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.startTime AS JobStartTime,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.endTime AS JobEndTime,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.billingTier AS BillingTier,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.totalBilledBytes AS TotalBilledBytes,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.totalProcessedBytes AS TotalProcessedBytes,
    protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.totalBilledBytes / 1000000000 AS TotalBilledGigabytes,
    (protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.totalBilledBytes / 1000000000) / 1000 AS TotalBilledTerabytes,
    ((protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.job.jobStatistics.totalBilledBytes / 1000000000) / 1000) * 5 AS TotalCost,
    protopayload_auditlog.requestMetadata.callerSuppliedUserAgent AS userAgent,
    protopayload_auditlog.authenticationInfo.principalEmail AS principalEmail,
    1 AS QueryCount
  FROM
  --<QUERY_REPLACE>replace variables with your own project and dataset id
    `%PROJECT_NAME%.%DATASET_NAME%.cloudaudit_googleapis_com_data_access_*`
  --</QUERY_REPLACE>
  WHERE
  --<QUERY_COMMENT>only parse completed queries
    protopayload_auditlog.serviceName = 'bigquery.googleapis.com'
    AND protopayload_auditlog.methodName = 'jobservice.jobcompleted'
    AND protopayload_auditlog.servicedata_v1_bigquery.jobCompletedEvent.eventName = 'query_job_completed' )
    --</QUERY_COMMENT>
---------------------------------------------------------------------------------
SELECT
  *,
  --<QUERY_COMMENT>LOGIC FOR QUERY GROUPING: Query desinationdatasets have weird hash names, overwrite with stale 'TEMP_HASH_DATASET'
  CASE
    WHEN DestinationTableId NOT LIKE 'anon%' THEN DestinationTableDatasetId
    ELSE 'TEMP_HASH_DATASET'
  END AS CleanDestinationTableDatasetId,
  --</QUERY_COMMENT>
  --<QUERY_COMMENT>LOGIC FOR QUERY GROUPING: A BQ Job in the log is either a Query or ETL job (scheduled, python/airflow, LOOKER PDT refresh)
  CASE
    WHEN DestinationTableId LIKE 'anon%' THEN 'Query'
    ELSE 'ETL'
  END AS JobType
  --</QUERY_COMMENT>
  --<QUERY_COMMENT>LOGIC FOR QUERY GROUPING: Using regex, extract all the tables-views from a query (string after FROM, JOIN) and return as unique sorted string
  ,ARRAY_TO_STRING(ARRAY(
    SELECT
      DISTINCT x
    FROM
      UNNEST(ARRAY_CONCAT(REGEXP_EXTRACT_ALL(Query,r"(?i)\s+(?:FROM|JOIN)\s+([^\s\(]+\.[^\s]+)") ) ) AS x
    ORDER BY
      x),', ') AS QueryTables
  --</QUERY_COMMENT>
  --<QUERY_COMMENT>LOGIC FOR QUERY GROUPING: Using regex, extract all the query WHERE,ON,AND - clause columns and return as a sorted string. Also, remove all LOOKER generated column names to keep this as clean as possible
  ,ARRAY_TO_STRING(ARRAY(
    SELECT
      DISTINCT x
    FROM
      UNNEST(ARRAY_CONCAT(REGEXP_EXTRACT_ALL( REGEXP_REPLACE( Query, r"(?i)\s+(z_+pivot_[a-z0-9_.]+)", ""),r"(?i)\s+(?:WHERE|AND|OR|ON)\s+(?:\s|\(|CAST|`)*([a-z0-9_.]+)(?:AND)?") ) ) AS x
    ORDER BY
      x),', ') AS QueryWhereColumns
   --</QUERY_COMMENT>
FROM
  vw
