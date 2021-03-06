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
               exdir = paste(save.path, "\\", ".", sep = ""))
  return(paste(save.path, "\\", "data", sep = ""))

}

#' Says Hello before the user start downloading everything
#'
#' @return MessageDownloader
#'
#' @export
#'
#' @examples
#'
MessageDownloader <- function(){
  print("Now the download will start, please be patient since it might take up to 2 minuts")
  downloadFireHolData()
  file.remove("master.zip")
  print("Download complete, thanks you for waiting")
}

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
  return(IPS)
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
tidyDataCountries <- function (raw.path) {
  # raw.path <- "data/geolite2_country/"
  raw.path <- paste(path.raw.data, "geolite2_country", sep="")
  raw.path <- paste(raw.path, "\\", sep="")
  temporary <- dir(path = raw.path, pattern="..\\continent_")
  file.remove(temporary)
  src.files <- list.files(path = raw.path, pattern = ".netset" )
  countries <- NULL

  for (file_name in src.files){
    file_info <- read.table(file = paste(raw.path, file_name, sep = ""),
                            comment.char="/", sep = "\t", stringsAsFactors = F,
                            nrows = 50, row.names = NULL)
    country_tmp <- dplyr::filter(file_info, stringr::str_detect(V1,"--"))
    tmp2 <- read.table(file = paste(raw.path, file_name, sep = ""),
                       skipNul = T, na.strings = "NULL", col.names = c("range"),
                       stringsAsFactors = F, row.names= NULL)

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
    return(df2[4])
  }else {
    return(FALSE)
  }
}

#' Internal function used to get each row in the IPS df
#' @param df
#' @param df2
#'
#'
#' @export
#'
ips_merge <- function(df_row,df2){
  if(iptools::is_ipv4(df_row[[1]])){
    for (i in 1:nrow(df2)) {
      df2_row <- df2[i,]
      if(iptools::ip_in_range(df_row[[1]],df2_row[[1]])){
        #location found
        #print(df2_row[4])
        df_row[3] <- df2_row[4]
        break
      }
    }
  } 
  else{
    df_row[3] <- Unknown
  }
  return (df_row[3])
}

#  if(iptools::is_ipv4(df_row[1])){
#    tmp <- apply(df2, 1, look_countries,df_row) #look for an IPv4
#    if(tmp != FALSE){
#      df_row[[3]] <- tmp
#    }
#  }
#  else {
#    tmp <- apply(df2, 1, look_countries2,df_row) #look for ranges
#    if(tmp != FALSE){
#      df_row[[3]] <- tmp
#    }
#  }
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
  #This solution is a bad one, because of the use of the for (we have to change it to apply method)
  for (i in 1:nrow(df){
    df[i,][3] <- ips_merge(df[i,], df2)
  }
  
  #apply(df,1,ips_merge,df2)
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


#' Return attack recount of an IP
#'
#' @param ip
#'
#' @return dataset
#' @export
#'
#' @examples
#' IPsRecount <- list.ip.count('5.188.86.174')
list.ip.count <- function(ip){
  IPsFound <- df[df$ip == ip,]

  return(sum(duplicated(IPsFound$ip)) + 1)
}

#' Show a dataset with a recount of attacks and countries of a selected IP
#'
#' @param ip
#'
#' @return dataset
#' @export
#'
#' @examples
#' IPRelatedDataset <- list.iprelated.dataset('5.188.86.174')
list.iprelated.dataset <- function(ip){
  IPsFound <- df[df$ip == ip,]

  count <- plyr::count(IPsFound)
  colnames(count)[4] <- "appearances"
  return(count)
}


#' Return all registered categories
#'
#'@param IPS
#'
#' @return list
#' @export
#'
#' @examples
#' ListCategories <- list.category()
list.category <- function(){
  return(dplyr::distinct(df[2]))
}

#' Return recount of registered attacks per category
#'
#' @param IPS
#'
#' @return dataset
#' @export
#'
#'
#' @examples
#' CategoriesCount <- list.category.count()
list.category.count <- function(){
  return(as.data.frame(table(df[2])))
}


#' Return a countries's list with victims's IPs that have been attacked
#'
#' @param IPS
#'
#' @return list
#' @export
#'
#' @examples
#' ListCountries <- list.country()
list.country <- function(){
  return (dplyr::distinct(df[3]))
}


#' Return dataset of recount of attacks registered for country
#'
#' @param IPS
#'
#' @return dataset
#' @export
#'
#' @examples
#' list.category.count()
list.country.count <- function(){
  return (table(df[3]))
}

