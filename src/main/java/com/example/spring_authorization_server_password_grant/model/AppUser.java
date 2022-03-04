package com.example.spring_authorization_server_password_grant.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Type;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.UUID;

@Data
@Entity
@Table(name = "app_users")
@NoArgsConstructor
public class AppUser implements Serializable {
   private static final long serialVersionUID = -1L;
   @Id
   @GeneratedValue(generator = "UUID")
   @Type(type = "uuid-char")
   private UUID id;
   private String password;
   private String firstName;
   private String lastName;
   private String loginId;
}
