
#' GetDataFrame
#'
#'
#'
#' @return dataset
#' @export
#'
#' @examples
getDataFrame <- function() {
  IPS <- data.frame(ip = character(),
                   categoria = character(),
                   pais = character(),
                   stringsAsFactors = F)
  print(save.path)
  return(IPS)
}


#' Downloads data from scratch.
#'
#' @param save.path
#'
#' @export
#'
#' @examples
downloadFireHolData <- function(save.path = tempdir()) {
  download.file(url = "https://github.com/firehol/blocklist-ipsets/archive/master.zip",
                destfile = paste(save.path, "\\", "master.zip", sep = ""))
  utils::unzip(zipfile = paste(save.path, "\\", "master.zip", sep = ""),
               exdir = paste(save.path, "\\", "data", sep = ""))
  #TODO: ELIMINAR FITXERS CONTINENT DINS DE GEOIP2 I QUADRAR PATHS
  return(paste(save.path, "\\", "data", sep = ""))
}


#' This function creates a data frame with all the malicious IPs from the downloaded sources
#'
#' @param working.directory
#'
#' @return ips
#' @export
#'
#' @examples
tidyDataIPs <- function(raw.path) {
  src.files <- list.files(path = raw.path, pattern = ".ipset")
  ips <- data.frame(ip = character(),
                    categ = character(),
                    country = character(),
                    stringsAsFactors = F)

  # file_name <- src.files[1]
  for (file_name in src.files){
    tmp <- read.table(file = paste(raw.path, file_name, sep = ""), skipNul = T,
                      col.names = c("ip"), na.strings = "NULL", stringsAsFactors = F)
    if (nrow(tmp) > 0) {
      file_info <- read.table(file = paste(raw.path, file_name, sep = ""),
                              comment.char="/", sep = "\t", quote = "", stringsAsFactors = F, nrows=50 )
      categ <- dplyr::filter(file_info, stringr::str_detect(V1,"Category"))
      if(nrow(categ) > 0) {
        categ <- stringr::str_trim(stringr::str_split(categ$V1, ":")[[1]][2])
        tmp$categ <- rep(x = categ, nrow(tmp))
        ips <- rbind(ips, tmp)
      }
    }
  }
  ips$country <- rep(x = " ", nrow(ips))
  return(ips)
}


#' This method collects data from the downloaded source and creates a data frame matching IP ranges and countries.
#'
#' @param working.directory
#'
#' @return countries
#' @export
#'
#' @examples
tidyDataCountries <- function(raw.path) {
  # raw.path <- "data/geolite2_country/"
  raw.path <- paste(path.raw.data, "geolite2_country", sep="")
  raw.path <- paste(raw.path, "\\", sep="")
  #TODO: S'HA D'ELIMINAR ELS FITXERS CONTINENT I ANONYMOUS.
  src.files <- list.files(path = raw.path, pattern = ".netset")
  countries <- NULL

  for (file_name in src.files){
    file_info <- read.table(file = paste(raw.path, file_name, sep = ""),
                            comment.char="/", sep = "\t", stringsAsFactors = F,
                            nrows = 50, row.names = NULL)
    country_tmp <- dplyr::filter(file_info, stringr::str_detect(V1,"--"))
    tmp2 <- read.table(file = paste(raw.path, file_name, sep = ""),
                       skipNul = T, na.strings = "NULL", col.names = c("range"),
                       stringsAsFactors = F, row.names= NULL)

    #sonip <- tmp2[sapply(tmp2$range, iptools::is_ipv4),]
    #nosonip <- tmp2[!sapply(tmp2$range, iptools::is_ipv4),]

    for (ip in tmp2) {
      tmp_boundary <- iptools::range_boundaries(ip)
      tmp2$min <- tmp_boundary[1]$minimum_ip
      tmp2$max <- tmp_boundary[2]$maximum_ip
    }
    if(nrow(country_tmp) > 0) {
      country <- stringr::str_trim(stringr::str_split(country_tmp$V1, "#")[[1]][2])
      country <- stringr::str_trim(stringr::str_split(country, ",")[[1]][1])
    }
    tmp2$country <- rep(x = country, nrow(tmp2))
    countries <- rbind(countries,tmp2)
  }
  return(countries)
}

#' Internal function used to look for the correct country
#'
#' @param rango
#' @param df2
#'
#' @return
#' @export
#'
#' @examples
look_countries2 <- function(df2, df_row){
  temp <- iptools::ip_in_range(rango, df2[1])
  if(test){
    print(rango)
    print(df2)
  }
}

#' Internal function used to look for the correct country
#'
#' @param rango
#' @param df2
#'
#' @return
#' @export
#'
#' @examples
look_countries <- function(df2, df_row){
  temp <- iptools::ip_in_range(df_row[1], df2[1])
  if (temp){
    return(df[4])
  }else {
    return(FALSE)
  }
}

#' Internal function used to get each row in the IPS df
#' @param df
#' @param df2
#'
#' @return df
#' @export
#'
ips_merge <- function(df_row,df2){
  country <- NULL
  if(iptools::is_ipv4(df_row[1])){
    tmp <- apply(df2, 1, look_countries,df_row) #look for an IPv4
    if(tmp != FALSE){
      df_row[[3]] <- tmp
    }
  }
  else {
    tmp <- apply(df2, 1, look_countries2,df_row) #look for ranges
    if(tmp != FALSE){
      df_row[[3]] <- tmp
    }
  }
  return(country)
}

#' This function merges the 2 dataframes in order to apply the location from countries' data frame to each IP from IPs.
#' This version uses the apply function cos am not able to get it working.
#'
#' @param df
#' @param df2
#'
#' @return
#' @export
#'
#' @examples
mergeDFs2 <- function (df,df2){
  final_df <- apply(df,1,ips_merge,df2)
  return(final_df)
}

#' This function merges the 2 dataframes in order to apply the location from countries to each IP from ips
#'
#' @param ips
#' @param countries
#'
#' @return final_ips
#' @export
#'
#' @examples
mergeDFs <- function(df,df2){

  #THIS BULLSHIT AIN'T WORKING -.-'
  for (filadf in df){
    ip <- filadf[[1]]
    if (iptools::is_ipv4(ip)){
      for(filadf2 in df2){
        rango <- filadf2[1]
        if (filadf2[2] != "Invalid"){ #it is an ip +a mask
          if (iptools::ip_in_range(ip, rango)){
            df[i,3] = df2[j,4]
          }
        }
        else { # compare IPs
          if (ip == rango) df[i,3] = df2[j,4]
        }
      }
    }
  }
  return(df)
}


#' A l'introduir una IP retorna la quantitat d'atacs rebuts
#'
#' @param ip
#'
#' @return dataset
#' @export
#'
#' @examples
#' IPsRecount <- list.ip.count('5.188.86.174')
list.ip.count <- function(ip){
  IPsFound <- IPS[IPS$ip == ip,]

  return(sum(duplicated(IPsFound$ip)) + 1)
}

#' A l'introduir una IP mostra el dataset dels atacs que ha rebut
#' classificada pel tipus de campanya i pais
#'
#' @param ip
#'
#' @return dataset
#' @export
#'
#' @examples
#' IPRelatedDataset <- list.iprelated.dataset('5.188.86.174')
list.iprelated.dataset <- function(ip){
  IPsFound <- IPS[IPS$ip == ip,]

  count <- plyr::count(IPsFound)
  colnames(count)[4] <- "appearances"
  return(count)
}


#' Mostra totes les categories que hi ha registrades
#'
#'@param IPS
#'
#' @return list
#' @export
#'
#' @examples
#' ListCategories <- list.category()
list.category <- function(IPS){
  return(dplyr::distinct(IPS[2]))
}

#' Retorna un dataset de quants atacs per categoria hi ha registrats
#'
#' @param IPS
#'
#' @return dataset
#' @export
#'
#'
#' @examples
#' CategoriesCount <- list.category.count()
list.category.count <- function(IPS){
  return(as.data.frame(table(IPS[2])))
}


#' Retorna un llistat dels països que tenen IPs que han sigut víctimes d'atacs
#'
#' @param IPS
#'
#' @return list
#' @export
#'
#' @examples
#' ListCountries <- list.country()
list.country <- function(){
  return (dplyr::distinct(IPS[3]))
}


#' Retorna un dataset de quants atacs per país hi ha registrats
#'
#' @param IPS
#'
#' @return dataset
#' @export
#'
#' @examples
#' list.category.count(IPS)
list.country.count <- function(IPS){
  return (table(IPS[3]))
}

