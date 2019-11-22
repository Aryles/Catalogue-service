package org.aryles.org.aryles.entities;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.Collection;

@Document
@Data @AllArgsConstructor @NoArgsConstructor @ToString
public class Category {
    @Id
    private String id;
    private String name;
    @DBRef
    private Collection<Product> products= new ArrayList<Product>();
}
