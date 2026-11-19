import sqlite3
import pytest
from services.traffic_rollup_service import compact_bridge_intervals,bridge_history_source_sql


def database():
    con=sqlite3.connect(':memory:')
    con.executescript('''CREATE TABLE traffic_intervals(ip TEXT,name TEXT,mac TEXT,downloaded_mb REAL,uploaded_mb REAL,total_mb REAL,live_bps REAL,day TEXT,ts TEXT);
      CREATE TABLE traffic_hourly_rollups(hour TEXT,day TEXT,ip TEXT,name TEXT,mac TEXT,downloaded_mb REAL,uploaded_mb REAL,total_mb REAL,avg_live_bps REAL,samples INTEGER,PRIMARY KEY(hour,ip));''')
    return con


def add(con,time,size,speed=100,ip='192.168.1.5'):
    con.execute('INSERT INTO traffic_intervals VALUES (?,?,?,?,?,?,?,?,?)',(ip,'Edited name','aa:bb',size,0,size,speed,'2026-11-19','2026-11-19 '+time))
    con.commit()


def total(con):return con.execute('SELECT SUM(total_mb) FROM ('+bridge_history_source_sql()+')').fetchone()[0]


def test_successive_partial_hour_batches_conserve_bytes_and_average_and_are_idempotent():
    con=database();add(con,'07:00:00',5,100);add(con,'07:20:00',7,200)
    with con:compact_bridge_intervals(con,'2026-11-19 07:10:00')
    assert total(con)==12
    add(con,'07:30:00',11,400)
    with con:compact_bridge_intervals(con,'2026-11-19 07:40:00')
    assert total(con)==23
    size,samples,speed=con.execute('SELECT total_mb,samples,avg_live_bps FROM traffic_hourly_rollups').fetchone()
    assert size==23 and samples==3 and speed==pytest.approx(700/3)
    with con:compact_bridge_intervals(con,'2026-11-19 07:40:00')
    assert total(con)==23 and con.execute('SELECT samples FROM traffic_hourly_rollups').fetchone()[0]==3


def test_late_arrivals_and_new_device_older_than_global_rollup_hour_stay_visible():
    con=database();add(con,'07:00:00',5)
    with con:compact_bridge_intervals(con,'2026-11-19 08:00:00')
    add(con,'06:15:00',4,ip='192.168.1.6')
    assert total(con)==9
    with con:compact_bridge_intervals(con,'2026-11-19 08:00:00')
    assert total(con)==9
    filtered=bridge_history_source_sql("ip='192.168.1.6'")
    assert con.execute('SELECT SUM(total_mb) FROM ('+filtered+')').fetchone()[0]==4


def test_failed_delete_rolls_back_aggregate_and_raw_rows_together():
    con=database();add(con,'07:00:00',5)
    con.execute("CREATE TRIGGER refuse_delete BEFORE DELETE ON traffic_intervals BEGIN SELECT RAISE(ABORT,'test interruption'); END")
    with pytest.raises(sqlite3.DatabaseError,match='test interruption'):
        with con:compact_bridge_intervals(con,'2026-11-19 08:00:00')
    assert total(con)==5
    assert con.execute('SELECT COUNT(*) FROM traffic_hourly_rollups').fetchone()[0]==0
    assert con.execute('SELECT COUNT(*) FROM traffic_intervals').fetchone()[0]==1


def test_exact_cutoff_is_preserved_for_the_next_batch():
    con=database();add(con,'07:10:00',5)
    with con:compact_bridge_intervals(con,'2026-11-19 07:10:00')
    assert con.execute('SELECT COUNT(*) FROM traffic_intervals').fetchone()[0]==1
    assert total(con)==5


@pytest.mark.parametrize('column',['downloaded_mb','uploaded_mb','total_mb'])
@pytest.mark.parametrize('null_position',['existing','batch'])
def test_nullable_counters_cannot_poison_later_valid_measurements(column,null_position):
    con=database();add(con,'07:00:00',3)
    with con:compact_bridge_intervals(con,'2026-11-19 07:10:00')
    con.execute(f'UPDATE traffic_hourly_rollups SET {column}=?',(None if null_position=='existing' else 3,));con.commit()
    add(con,'07:20:00',5)
    con.execute(f'UPDATE traffic_intervals SET {column}=?',(5 if null_position=='existing' else None,));con.commit()
    with con:compact_bridge_intervals(con,'2026-11-19 07:30:00')
    expected=5 if null_position=='existing' else 3
    assert con.execute(f'SELECT {column} FROM traffic_hourly_rollups').fetchone()[0]==expected


def test_missing_rates_remain_unknown_independent_of_batch_partition():
    together=database();split=database()
    for index,speed in enumerate([100,None,200]):
        add(together,f'07:{index}0:00',1,speed)
        add(split,f'07:{index}0:00',1,speed)
        with split:compact_bridge_intervals(split,'2026-11-19 08:00:00')
    with together:compact_bridge_intervals(together,'2026-11-19 08:00:00')
    assert together.execute('SELECT avg_live_bps FROM traffic_hourly_rollups').fetchone()[0] is None
    assert split.execute('SELECT avg_live_bps FROM traffic_hourly_rollups').fetchone()[0] is None
    assert total(together)==total(split)==3


def test_collector_freezes_selection_and_deletion_cutoff_once(monkeypatch):
    import live_packet_collector as collector
    from services import traffic_rollup_service as rollups
    calls=[]
    class Connection:
        def execute(self,sql,params=()):
            calls.append((sql,params));return self
        def fetchone(self):return ('2026-11-19 10:10:00',)
        def commit(self):pass
        def rollback(self):raise AssertionError('Unexpected rollback')
        def close(self):pass
    monkeypatch.setattr(collector,'connect_db',lambda:Connection())
    monkeypatch.setattr(rollups,'compact_bridge_intervals',lambda con,cutoff:calls.append(('bridge',cutoff)))
    collector.rollup_and_prune_raw_traffic({'raw_traffic_retention_hours':2,'traffic_retention_days':60})
    assert ('bridge','2026-11-19 10:10:00') in calls
    for sql,params in calls:
        if 'WHERE ts < ?' in sql:assert params==('2026-11-19 10:10:00',)


def attached_database(tmp_path):
    path=tmp_path/'traffic.db'
    with sqlite3.connect(path) as disk:database().backup(disk)
    def connect():
        con=sqlite3.connect(tmp_path/'app.db',timeout=0.1)
        con.execute('ATTACH DATABASE ? AS trafficdb',(str(path),))
        con.execute('PRAGMA trafficdb.journal_mode=WAL')
        return con
    return path,connect


def test_attached_wal_readers_see_old_snapshot_and_concurrent_writer_cannot_slip_between_archive_and_delete(tmp_path):
    import threading
    path,connect=attached_database(tmp_path)
    seed=connect();add(seed,'07:00:00',5);seed.close()
    archived=threading.Event();release=threading.Event();errors=[]
    def worker():
        con=connect()
        class PauseDelete:
            def __getattr__(self,name):return getattr(con,name)
            def execute(self,sql,params=()):
                if sql.startswith('DELETE FROM traffic_intervals'):
                    archived.set();assert release.wait(5)
                return con.execute(sql,params)
        try:
            with con:compact_bridge_intervals(PauseDelete(),'2026-11-19 08:00:00')
        except BaseException as error:errors.append(error)
        finally:con.close()
    thread=threading.Thread(target=worker);thread.start()
    reader=sqlite3.connect(path,timeout=0.1)
    try:
        assert archived.wait(5)
        assert total(reader)==5
        assert reader.execute('SELECT COUNT(*) FROM traffic_intervals').fetchone()[0]==1
        assert reader.execute('SELECT COUNT(*) FROM traffic_hourly_rollups').fetchone()[0]==0
        with pytest.raises(sqlite3.OperationalError,match='locked'):
            reader.execute("INSERT INTO traffic_intervals (ip,ts,total_mb) VALUES ('192.168.1.6','2026-11-19 06:00:00',7)")
        reader.rollback()
    finally:
        release.set();thread.join(5)
    assert not thread.is_alive() and not errors
    assert total(reader)==5
    add(reader,'06:00:00',7,ip='192.168.1.6')
    assert total(reader)==12
    with reader:compact_bridge_intervals(reader,'2026-11-19 08:00:00')
    assert total(reader)==12
    assert reader.execute('SELECT SUM(downloaded_mb),SUM(uploaded_mb),SUM(samples) FROM traffic_hourly_rollups').fetchone()==(12,0,2)
    assert reader.execute('SELECT COUNT(*) FROM traffic_intervals').fetchone()[0]==0
    reader.close()


def test_real_caller_later_statement_failure_rolls_back_attached_bridge_before_retry(tmp_path,monkeypatch):
    import live_packet_collector as collector
    from datetime import datetime,timedelta
    path,connect=attached_database(tmp_path)
    con=connect();stamp=(datetime.now()-timedelta(days=10)).strftime('%Y-%m-%d %H:%M:%S')
    # A timestamp certainly older than the retention cutoff; only the bridge
    # tables exist, so a later legacy-table statement deliberately fails.
    con.execute("INSERT INTO traffic_intervals VALUES ('192.168.1.5','name','mac',5,2,7,100,?,?)",(stamp[:10],stamp))
    con.commit();con.close()
    monkeypatch.setattr(collector,'connect_db',connect)
    collector.rollup_and_prune_raw_traffic({'raw_traffic_retention_hours':2,'traffic_retention_days':3650})
    check=connect()
    assert check.execute('SELECT COUNT(*) FROM traffic_intervals').fetchone()[0]==1
    assert check.execute('SELECT COUNT(*) FROM traffic_hourly_rollups').fetchone()[0]==0
    with check:compact_bridge_intervals(check,datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    assert check.execute('SELECT SUM(downloaded_mb),SUM(uploaded_mb),SUM(total_mb),SUM(samples) FROM traffic_hourly_rollups').fetchone()==(5,2,7,1)
    assert total(check)==7
    check.close()


def test_explicit_transaction_protects_legacy_autocommit_connection():
    con=database();add(con,'07:00:00',5);con.isolation_level=None
    con.execute("CREATE TRIGGER refuse_delete BEFORE DELETE ON traffic_intervals BEGIN SELECT RAISE(ABORT,'interrupted'); END")
    with pytest.raises(sqlite3.DatabaseError):
        with con:compact_bridge_intervals(con,'2026-11-19 08:00:00')
    assert total(con)==5 and con.execute('SELECT COUNT(*) FROM traffic_hourly_rollups').fetchone()[0]==0


def test_byte_originated_real_values_remain_exact_within_binary64_integer_range():
    con=database();mib=1048576
    for index,size in enumerate([2**50+1,3,5]):
        add(con,f'07:{index}0:00',size/mib)
        with con:compact_bridge_intervals(con,'2026-11-19 08:00:00')
    assert round(total(con)*mib)==2**50+9


def test_checkpoint_failure_is_reported_as_deferred_after_durable_commit(tmp_path,monkeypatch,capsys):
    import live_packet_collector as collector
    from datetime import datetime,timedelta
    path,connect=attached_database(tmp_path);con=connect()
    stamp=(datetime.now()-timedelta(days=10)).strftime('%Y-%m-%d %H:%M:%S')
    con.execute("INSERT INTO traffic_intervals VALUES ('192.168.1.5','name','mac',5,2,7,100,?,?)",(stamp[:10],stamp));con.commit();con.close()
    class LegacyTablesEmpty:
        def __init__(self):self.con=connect()
        def __getattr__(self,name):return getattr(self.con,name)
        def execute(self,sql,params=()):
            if 'wal_checkpoint' in sql:raise sqlite3.OperationalError('busy checkpoint')
            if any(name in sql for name in ['estimated_app','remote_traffic','classified_flow','traffic_samples']):return None
            return self.con.execute(sql,params)
    monkeypatch.setattr(collector,'connect_db',LegacyTablesEmpty)
    collector.rollup_and_prune_raw_traffic({'raw_traffic_retention_hours':2,'traffic_retention_days':3650})
    message=capsys.readouterr().out
    assert 'committed; checkpoint deferred' in message and 'cleanup failed' not in message
    check=connect();assert total(check)==7
    assert check.execute('SELECT COUNT(*) FROM traffic_intervals').fetchone()[0]==0
    check.close()
