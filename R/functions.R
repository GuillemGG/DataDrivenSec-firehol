
#' Title GetDataFrame
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
#' @return
#' @export
#'
#' @examples
downloadFireHolData <- function(save.path = tempdir()) {
  # download.file()
  print("Data downloaded") #Fake by now. Has to be done manually.
}


#' Tidying IP dataset
#'
#' @param
#'
#' @return
#' @export
#'
#' @examples
tidyDataIPs <- function(working.directory) {
  setwd(working.directory)
  src.files <- list.files() # LLEGIR FITXERS DEL WORKING DIRECTORY
  IPS <- NULL

  for (file_name in src.files){
    tmp <- read.table(file = paste(working.directory, file_name, sep = "\\"), skipNul = T,
                      col.names = c("ip"), na.strings = "NULL", stringsAsFactors = F)
    file_info <- read.table(file=file_name, comment.char="/", sep = "\t", stringsAsFactors = F,nrows=50 )
    categ <- dplyr::filter(file_info, stringr::str_detect(V1,"Category"))
    if(nrow(categ) > 0) {
      categ <- stringr::str_trim(stringr::str_split(categ$V1, ":")[[1]][2])
      tmp$categ <- rep(x = categ, nrow(tmp))
      print(file_name)
      IPS <- rbind(IPS, tmp)
    }
  }
  return()
}


#' Tidying Countries dataset
#'
#' @param
#'
#' @return
#' @export
#'
#' @examples
tidyDataCountries <- function(working.directory) {
  setwd(working.directory) # WORKING DIRECTORY
  src.files <- list.files()
  countries <- NULL

  for (file_name in src.files){
    file_info <- read.table(file=file_name, comment.char="/", sep = "\t", stringsAsFactors = F,nrows=50, row.names = NULL)
    country_tmp <- dplyr::filter(file_info, stringr::str_detect(V1,"--"))
    tmp2 <- read.table(file = paste(working.directory,file_name,
                                    sep = "\\"),skipNul = T, na.strings = "NULL", col.names = c("range"), stringsAsFactors = F, row.names= NULL)
    for (ip in tmp2) {
      tmp_boundary <- range_boundaries(ip)
      tmp2$min <- tmp_boundary[1]
      tmp2$max <- tmp_boundary[2]
    }
    if(nrow(country_tmp) > 0) {
      country <- stringr::str_trim(stringr::str_split(country_tmp$V1, "#")[[1]][2])
      country <- stringr::str_trim(stringr::str_split(country, ",")[[1]][1])
      print(file_name)
    }
    tmp2$country <- rep(x = country, nrow(tmp2))
    countries <- rbind(countries,tmp2)
  }
  return countries()
}

#' A l'introduir una IP mostra el dataset dels atacs que ha rebut
#' classificada pel tipus de campanya i país
#'
#' @param df
#' @param ip
#'
#' @return dataset
#' @export
#'
#' @examples
#' IPsRecount <- list.ip.count(IPS, '5.188.86.174')
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

IPsRecount <- list.ip.count(IPS, '5.188.86.174')


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
#' @return
#' @export dataset
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
#' @return list
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
#' @return dataset
#' @export
#'
#' @examples
#' list.category.count(IPS)
list.country.count <- function(df){
  print (table(df[3]))
}
