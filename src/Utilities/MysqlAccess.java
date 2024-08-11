package Utilities;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.util.Properties;
import java.util.Scanner;
import javax.sql.DataSource;

public class MysqlAccess {

    public static Properties property = null;
    public static String ErrorSet = null;
    public static DataSource dataSourcePool ;
    private String host;
    private String user;
    private String password;

    public DataSource getDataSource() {
        System.out.println("Enter hostname: ");
        Scanner obj = new Scanner(System.in);
        host = obj.nextLine();
        String port = "3306";
        String schema = "data";
        String url = "jdbc:mysql://" + host + ":" + port + "/" + schema + "?serverTimezone=UTC&tcpKeepAlive=true&autoReconnect=true&useSSL=false&connectionAttributes=program_name:myproject";
        
        HikariConfig config = new HikariConfig();
        config.setDriverClassName("com.mysql.cj.jdbc.Driver");
        config.setJdbcUrl(url);
        config.setUsername(user);
        config.setPassword(password);
        config.setMinimumIdle(5);
        config.setMaximumPoolSize(100);
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        
        return new HikariDataSource(config);
    }
    public MysqlAccess(String user, String password) {
        this.user = user;
        this.password = password;
        this.dataSourcePool = getDataSource();
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
