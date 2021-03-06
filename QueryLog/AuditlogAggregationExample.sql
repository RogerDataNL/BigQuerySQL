/*
  <PURPOSE>
  Example query that uses the BigQuery audit VIEW to investigate Query usage costs per set of tables in the SELECT /JOIN statement of the query
  </PURPOSE>
  <USAGE>
  -1st, create the auditlog view: https://github.com/RogerDataNL/BigQuerySQL/blob/master/QueryLog/AuditlogAggregation.sql
  -2nd, change the project / dataset in the <QUERY_REPLACE> tag and run / test the query
  </USAGE>
  <AUTHOR>Rogier Werschkull (RogerData)</AUTHOR>
	<LAST_UPDATE>22-01-2019</LAST_UPDATE>
*/
WITH
  vw AS (
  SELECT
    ProjectId,
    DestinationTableProjectId,
    CleanDestinationTableDatasetId,
    JobType,
    QueryTables,
    CleanDestinationTableId,
    QueryWhereColumns,
    ARRAY_TO_STRING(ARRAY_AGG(DISTINCT UserId),', ') AS UserIds,
    MAX(Query) AS QueryExample,
    MIN(Query) AS AnotherQueryExample,
    MAX(JobId) AS JobExample,
    MIN(JobStartTime) AS MinJobStartTime,
    MAX(JobStartTime) AS MaxJobStartTime,
    SUM(TotalBilledGigabytes) AS TotalBilledGigabytes,
    SUM(TotalCost) AS JobCosts,
    COUNT(1) AS NrOfJobs
  FROM
  --<QUERY_REPLACE>
    `%PROJECT_NAME%.%DATASET_NAME%.%Querylog_view%`
  --</QUERY_REPLACE>
  WHERE
    LogDate>=FORMAT_DATE("%Y%m%d", DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
  GROUP BY
    1,
    2,
    3,
    4,
    5,
    6,
    7
  HAVING
    JobCosts>0 )
---------------------------------------------------------------------------------------
SELECT
  *,
  ROW_NUMBER() OVER (PARTITION BY QueryTables ORDER BY JobCosts DESC) AS QueryTablePatternNumber,
  SUM(JobCosts) OVER (PARTITION BY QueryTables) AS TotalCostPerQueryTables,
  SUM(JobCosts) OVER () AS TotalCosts
FROM
  vw
ORDER BY
  --use this for cost sorting 'per querytables set'--> this is the logical starting point to start optimizing usage costs:
  TotalCostPerQueryTables DESC,
  JobPattern_nr ASC
