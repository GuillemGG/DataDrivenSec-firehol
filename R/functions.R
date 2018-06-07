
#' GetDataFrame
#'
#' @param still on development
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
  print("Data downloaded") #Fake by now. Has to be done manually.
  return(paste(save.path, "\\", "data", sep = ""))
}


#' Tidying IP dataset
#'
#' @param working.directory
#'
#' @return
#' @export
#'
#' @examples
tidyDataIPs <- function(raw.path) {
  src.files <- list.files(path = raw.path, pattern = ".ipset")
  ips <- data.frame(ip = character(),
                    categ = character(),
                    stringsAsFactors = F)

  # file_name <- src.files[1]
  for (file_name in src.files[1:30]){
    tmp <- read.table(file = paste(raw.path, file_name, sep = ""), skipNul = T,
                      col.names = c("ip"), na.strings = "NULL", stringsAsFactors = F)
    if (nrow(tmp) > 0) {
      file_info <- read.table(file = paste(raw.path, file_name, sep = ""),
                              comment.char="/", sep = "\t", stringsAsFactors = F, nrows=50 )
      categ <- dplyr::filter(file_info, stringr::str_detect(V1,"Category"))
      if(nrow(categ) > 0) {
        categ <- stringr::str_trim(stringr::str_split(categ$V1, ":")[[1]][2])
        tmp$categ <- rep(x = categ, nrow(tmp))
        ips <- rbind(ips, tmp)
      }
    }
  }
  return(ips)
}


#' Tidying Countries dataset
#'
#' @param working.directory
#'
#' @return
#' @export
#'
#' @examples
tidyDataCountries <- function(working.directory) {
  setwd(working.directory) # WORKING DIRECTORY
  # raw.path <- "data/geolite2_country/"

  src.files <- list.files()
  countries <- NULL

  for (file_name in src.files){
    file_info <- read.table(file = paste(raw.path, file_name, sep = ""),
                            comment.char="/", sep = "\t", stringsAsFactors = F,
                            nrows = 50, row.names = NULL)
    country_tmp <- dplyr::filter(file_info, stringr::str_detect(V1,"--"))
    tmp2 <- read.table(file = paste(raw.path, file_name, sep = ""),
                       skipNul = T, na.strings = "NULL", col.names = c("range"),
                       stringsAsFactors = F, row.names= NULL)

    sonip <- tmp2[sapply(tmp2$range, iptools::is_ipv4),]
    nosonip <- tmp2[!sapply(tmp2$range, iptools::is_ipv4),]

    for (ip in tmp2) {
      tmp_boundary <- iptools::range_boundaries(ip)
      tmp2$min <- tmp_boundary[1]$minimum_ip
      tmp2$max <- tmp_boundary[2]$maximum_ip
    }
    if(nrow(country_tmp) > 0) {
      country <- stringr::str_trim(stringr::str_split(country_tmp$V1, "#")[[1]][2])
      country <- stringr::str_trim(stringr::str_split(country, ",")[[1]][1])
      print(file_name)
    }
    tmp2$country <- rep(x = country, nrow(tmp2))
    countries <- rbind(countries,tmp2)
  }
  return()
}


list.ip.count <- function(df, ip){
  mydf <- (as.data.frame(table(df[1])))
  mytable <- table(df[1])
  #t <- table(df[1])
  #print(which(mydf == ip))
  #print(mydf[957])
  print(dplyr::filter(str_detect(mytable, ip)))
  print(mytable[mytable[,1]==ip,1])

  dplyr::filter(file_info, stringr::str_detect(V1,"--"))
}

#' Mostra totes les categories que hi ha registrades
#'
#' @param df
#'
#' @return list
#' @export
#'
#' @examples
#' ListCategories <- list.category(IPS)
list.category <- function(df){
  print (dplyr::distinct(df[2]))
}


#' Retorna un dataset de quants atacs per categoria hi ha registrats
#'
#' @param df
#'
#' @export
#'
#' @examples
#' CategoriesCount <- list.category.count(IPS)
list.category.count <- function(df){
  print(as.data.frame(table(df[2])))
}


#' Retorna un llistat dels països que tenen IPs que han sigut víctimes d'atacs
#'
#' @param df
#'
#' @export
#'
#' @examples
#' ListCountries <- list.country(IPS)
list.country <- function(df){
  print (dplyr::distinct(df[3]))
}


#' Retorna un dataset de quants atacs per país hi ha registrats
#'
#' @param df
#'
#' @export
#'
#' @examples
#' list.category.count(IPS)
list.country.count <- function(df){
  print (table(df[3]))
}

